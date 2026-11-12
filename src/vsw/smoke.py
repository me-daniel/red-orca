"""M0 smoke: one small coding-and-review task through the real gateway."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
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
from .domain import Status, TaskEnvelope
from .util import utc_now

SPEC = """Write Python 3 code for this specification.

Function: clamp(value, low, high)
- Return value when low <= value <= high
- Return low when value < low
- Return high when value > high
- Raise ValueError when low > high
- Accept ints and floats
- No prints, no global state, no file or network I/O

Return only the function definition. No markdown fences, no tests, no explanation.
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


def extract_code(text: str) -> str:
    text = text.strip()
    if "```" in text:
        blocks = re.findall(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
        if blocks:
            text = max(blocks, key=len).strip()
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(("def ", "class ", "@", "import ", "from ")):
            return "\n".join(lines[index:]).strip() + "\n"
    return text + "\n"


def _verdict(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip().strip("*` ").upper()
        if stripped.startswith(("APPROVED", "CHANGES_REQUESTED", "INCONCLUSIVE")):
            return stripped.split()[0]
    return None


def _run_tests(run_dir: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "-v", "test_clamp"],
        cwd=str(run_dir),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _mock_adapters() -> dict[str, Adapter]:
    def implement(envelope: TaskEnvelope, prompt: str) -> AdapterOutput:
        return AdapterOutput(text=MOCK_IMPLEMENTATION, duration_s=0.0)

    def review(envelope: TaskEnvelope, prompt: str) -> AdapterOutput:
        return AdapterOutput(
            text="APPROVED\nMock review: tests define the behavior.", duration_s=0.0
        )

    return {"claude": MockAdapter(implement), "codex": MockAdapter(review)}


def run_smoke(mode: str = "mock", root: Path | None = None) -> dict[str, Any]:
    root = root or repo_root()
    limits = load_limits(root)
    budget = Budget(limits)
    adapters: dict[str, Adapter] | None = _mock_adapters() if mode == "mock" else None
    gateway = CodingAgentGateway(limits, budget, adapters=adapters, root=root)

    run_id = time.strftime("smoke-%Y%m%d-%H%M%S", time.gmtime())
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "run_id": run_id,
        "stage": "M0",
        "mode": mode,
        "started": utc_now(),
        "checks": [],
        "results": [],
    }

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"name": name, "ok": ok, "detail": detail})

    impl_env = TaskEnvelope(
        id=f"{run_id}-impl",
        purpose="implement clamp",
        family="claude",
        label="sonnet",
        effort="high",
        budget_usd=limits.max_task_budget_usd,
        timeout_s=limits.per_call_timeout_seconds,
        permitted_paths=[f"runs/{run_id}/**"],
    )
    impl = gateway.run(impl_env, SPEC)
    report["results"].append(impl.model_dump(mode="json"))
    check("implement_completed", impl.status == Status.COMPLETED, impl.status.value)
    if impl.status != Status.COMPLETED:
        return _finish(report, run_dir, budget)

    code = extract_code(impl.output)
    (run_dir / "clamp.py").write_text(code, encoding="utf-8")
    (run_dir / "test_clamp.py").write_text(TESTS, encoding="utf-8")
    test_rc, test_output = _run_tests(run_dir)
    (run_dir / "test_output.txt").write_text(test_output, encoding="utf-8")
    check("tests_pass", test_rc == 0, test_output.strip().splitlines()[-1] if test_output else "")

    review_env = TaskEnvelope(
        id=f"{run_id}-review",
        purpose="review clamp implementation",
        family="codex",
        label="gpt-6.1-sol",
        effort="high",
        budget_usd=limits.max_task_budget_usd,
        timeout_s=limits.per_call_timeout_seconds,
        permitted_paths=[],
    )
    review_prompt = f"""Independent code review. Do not use tools.

SPECIFICATION:
{SPEC}

CODE:
```python
{code}
```

TEST RESULT (exit code {test_rc}):
{test_output[-3000:]}

Reply with exactly one of these on the first line: APPROVED, CHANGES_REQUESTED, INCONCLUSIVE.
Then list up to 5 concrete findings, or write "No issues found."
"""
    review = gateway.run(review_env, review_prompt)
    report["results"].append(review.model_dump(mode="json"))
    check("review_completed", review.status == Status.COMPLETED, review.status.value)
    verdict = _verdict(review.output) if review.status == Status.COMPLETED else None
    check("review_verdict", verdict == "APPROVED", f"verdict={verdict}")

    report["artifacts"] = {
        "clamp": str(run_dir / "clamp.py"),
        "tests": str(run_dir / "test_clamp.py"),
        "test_output": str(run_dir / "test_output.txt"),
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
            f"- **{result['model_requested']}** status={result['status']} "
            f"model_actual={result.get('model_actual')} "
            f"effort={result.get('effort_actual')} cost=${result.get('cost_usd', 0):.4f}"
        )
        for limitation in result.get("limitations", []):
            lines.append(f"  - limitation: {limitation}")
    (run_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    report["run_dir"] = str(run_dir)
    return report
