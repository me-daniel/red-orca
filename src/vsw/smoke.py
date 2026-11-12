"""Smoke: Claude advises, Codex implements in a worktree, Codex reviews the diff.

The three calls exercise the enforced role split rather than relying on prompt
wording: the adviser gets no tools, the implementer runs in its own worktree and
must stay inside the permitted paths, and the reviewer runs read-only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .budget import Budget
from .coding_agent_gateway import (
    Adapter,
    AdapterOutput,
    CodingAgentGateway,
    MockAdapter,
)
from .config import load_limits, repo_root
from .domain import Role, Status, TaskEnvelope
from .util import new_run_dir, utc_now

SPEC = """Write Python 3 code for this specification.

Function: clamp(value, low, high)
- Return value when low <= value <= high
- Return low when value < low
- Return high when value > high
- Raise ValueError when low > high
- Accept ints and floats
- No prints, no global state, no file or network I/O
"""

TESTS = """import unittest

from clamp import clamp


class ClampTests(unittest.TestCase):
    def test_inside(self):
        self.assertEqual(clamp(5, 1, 10), 5)

    def test_below(self):
        self.assertEqual(clamp(-3, 1, 10), 1)

    def test_above(self):
        self.assertEqual(clamp(99, 1, 10), 10)

    def test_bounds(self):
        self.assertEqual(clamp(1, 1, 10), 1)
        self.assertEqual(clamp(10, 1, 10), 10)

    def test_floats(self):
        self.assertEqual(clamp(2.5, 1.0, 3.0), 2.5)

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            clamp(5, 10, 1)


if __name__ == "__main__":
    unittest.main()
"""

MOCK_IMPLEMENTATION = """def clamp(value, low, high):
    if low > high:
        raise ValueError("low must not exceed high")
    return max(low, min(value, high))
"""

ADVICE_PROMPT = f"""You are advising, not implementing. Do not write code.

SPECIFICATION:
{SPEC}

List exactly two edge cases the implementation must handle and one likely bug.
Under 120 words. No code blocks."""

IMPLEMENT_PROMPT = f"""Implement this in the repository root. Create exactly two files:
`clamp.py` and `test_clamp.py`. Do not touch anything else.

SPECIFICATION:
{SPEC}

REQUIRED TESTS for `test_clamp.py`:
{TESTS}

ADVISER NOTES:
{{advice}}
"""


def _verdict(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip().strip("*` ").upper()
        if stripped.startswith(("APPROVED", "CHANGES_REQUESTED", "INCONCLUSIVE")):
            return stripped.split()[0]
    return None


def _mock_adapters() -> dict[str, Adapter]:
    def advise(envelope: TaskEnvelope, prompt: str) -> AdapterOutput:
        return AdapterOutput(
            text="Two edge cases: low > high, and float bounds. Likely bug: off-by-one "
            "when value equals a bound.",
            duration_s=0.0,
        )

    def review(envelope: TaskEnvelope, prompt: str) -> AdapterOutput:
        return AdapterOutput(
            text="APPROVED\nMock review: the diff matches the spec.", duration_s=0.0
        )

    return {
        "claude": MockAdapter(advise),
        "codex": MockAdapter(
            review, files={"clamp.py": MOCK_IMPLEMENTATION, "test_clamp.py": TESTS}
        ),
    }


def run_smoke(mode: str = "mock", root: Path | None = None) -> dict[str, Any]:
    root = root or repo_root()
    limits = load_limits(root)
    budget = Budget(limits)
    adapters: dict[str, Adapter] | None = _mock_adapters() if mode == "mock" else None
    gateway = CodingAgentGateway(limits, budget, adapters=adapters, root=root)

    run_id, run_dir = new_run_dir(root, "smoke")
    report: dict[str, Any] = {
        "run_id": run_id,
        "stage": "M0",
        "mode": mode,
        "roles": {"advice": "claude", "implement": "codex", "review": "codex"},
        "started": utc_now(),
        "checks": [],
        "results": [],
    }

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"name": name, "ok": ok, "detail": detail})

    # 1. Claude advises. Text only, no tools, no worktree.
    advice_env = TaskEnvelope(
        id=f"{run_id}-advice",
        purpose="advise on clamp edge cases",
        family="claude",
        label="opus",
        effort="medium",
        role=Role.ADVICE,
        budget_usd=limits.max_task_budget_usd,
        timeout_s=limits.per_call_timeout_seconds,
        permitted_paths=[],
    )
    advice = gateway.run(advice_env, ADVICE_PROMPT)
    report["results"].append(advice.model_dump(mode="json"))
    check("advice_completed", advice.status == Status.COMPLETED, advice.status.value)
    check(
        "advice_text_only",
        not advice.changed_files,
        f"changed={advice.changed_files}" if advice.changed_files else "no repository changes",
    )
    if advice.status != Status.COMPLETED:
        return _finish(report, run_dir, budget)

    # 2. Codex implements in an isolated worktree; the diff is captured, not applied.
    impl_env = TaskEnvelope(
        id=f"{run_id}-impl",
        purpose="implement clamp",
        family="codex",
        label="gpt-6.1-sol",
        effort="high",
        role=Role.IMPLEMENT,
        budget_usd=limits.max_task_budget_usd,
        timeout_s=limits.implementation_timeout_seconds,
        permitted_paths=["clamp.py", "test_clamp.py"],
        pytest_paths=["test_clamp.py"],
    )
    impl = gateway.run(impl_env, IMPLEMENT_PROMPT.format(advice=advice.output))
    report["results"].append(impl.model_dump(mode="json"))
    check("implement_completed", impl.status == Status.COMPLETED, impl.status.value)
    outside = [path for path in impl.changed_files if path not in {"clamp.py", "test_clamp.py"}]
    check(
        "changed_files_within_bounds",
        impl.status == Status.COMPLETED and not outside,
        f"changed={impl.changed_files} outside={outside}",
    )
    check(
        "tests_pass",
        bool(impl.tests.get("ok")),
        str(impl.tests.get("detail", "no tests were run")),
    )
    if impl.status != Status.COMPLETED:
        return _finish(report, run_dir, budget)

    # 3. Codex reviews the captured diff read-only.
    review_env = TaskEnvelope(
        id=f"{run_id}-review",
        purpose="review clamp implementation",
        family="codex",
        label="gpt-6.1-sol",
        effort="high",
        role=Role.REVIEW,
        budget_usd=limits.max_task_budget_usd,
        timeout_s=limits.per_call_timeout_seconds,
        permitted_paths=[],
    )
    review_prompt = f"""Independent code review. Read-only; do not modify files.

SPECIFICATION:
{SPEC}

DIFF UNDER REVIEW (files: {impl.changed_files}):
```diff
{impl.diff[:12000]}
```

TEST RESULT: {impl.tests.get("ok")} ({impl.tests.get("detail", "")})

Reply with exactly one of these on the first line: APPROVED, CHANGES_REQUESTED, INCONCLUSIVE.
Then list up to 5 concrete findings, or write "No issues found."
"""
    review = gateway.run(review_env, review_prompt)
    report["results"].append(review.model_dump(mode="json"))
    check("review_completed", review.status == Status.COMPLETED, review.status.value)
    verdict = _verdict(review.output) if review.status == Status.COMPLETED else None
    check("review_verdict", verdict == "APPROVED", f"verdict={verdict}")

    report["artifacts"] = {
        "patch": impl.patch_path,
        "changed_files": impl.changed_files,
    }
    return _finish(report, run_dir, budget)


def _finish(report: dict[str, Any], run_dir: Path, budget: Budget) -> dict[str, Any]:
    report["finished"] = utc_now()
    report["budget"] = budget.status()
    report["status"] = "pass" if all(c["ok"] for c in report["checks"]) else "fail"
    (run_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    lines = [
        f"# M0 smoke — {report['run_id']}",
        "",
        f"Mode: **{report['mode']}**",
        f"Status: **{report['status']}**",
        "",
        "| Check | Result | Detail |",
        "| --- | --- | --- |",
    ]
    for item in report["checks"]:
        lines.append(f"| {item['name']} | {'PASS' if item['ok'] else 'FAIL'} | {item['detail']} |")
    lines += ["", "## Delegates", ""]
    for result in report["results"]:
        lines.append(
            f"- **{result['model_requested']}** role={result.get('role')} status={result['status']} "
            f"model_actual={result.get('model_actual')} "
            f"effort={result.get('effort_actual')} cost=${result.get('cost_usd', 0):.4f}"
        )
        for limitation in result.get("limitations", []):
            lines.append(f"  - limitation: {limitation}")
        if result.get("changed_files"):
            lines.append(f"  - changed: {', '.join(result['changed_files'])}")
    (run_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    report["run_dir"] = str(run_dir)
    return report
