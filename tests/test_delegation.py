"""The role split, role-aware timeouts, and the changed-file boundary."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from vsw.budget import Budget
from vsw.coding_agent_gateway import (
    AdapterOutput,
    ClaudeCliAdapter,
    CodexCliAdapter,
    CodingAgentGateway,
    apply_reviewed_patch,
    reject_outside_paths,
)
from vsw.config import Limits, load_limits
from vsw.domain import Role, Status, TaskEnvelope
from vsw.policy import ROLE_ALLOWLIST, Route, RoutingDenied, enforce_role

LIMITS = Limits()


def envelope(**overrides: Any) -> TaskEnvelope:
    data: dict[str, Any] = {
        "id": "t1",
        "purpose": "delegated task",
        "family": "codex",
        "label": "gpt-6.1-sol",
        "effort": "high",
        "role": Role.IMPLEMENT,
        "budget_usd": 0.5,
        "permitted_paths": ["src/**"],
    }
    data.update(overrides)
    return TaskEnvelope(**data)


class RecordingAdapter:
    """Captures the timeout the gateway chose, and optionally writes files."""

    def __init__(self, files: dict[str, str] | None = None, text: str = "done") -> None:
        self.files = files or {}
        self.text = text
        self.timeouts: list[float] = []

    def run(self, envelope, route, prompt, timeout, workdir=None):  # type: ignore[no-untyped-def]
        self.timeouts.append(timeout)
        if self.files and workdir is not None and envelope.role is Role.IMPLEMENT:
            for name, content in self.files.items():
                target = workdir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
        return AdapterOutput(text=self.text)


def gateway(root: Path, adapters: dict[str, Any], limits: Limits = LIMITS) -> CodingAgentGateway:
    return CodingAgentGateway(limits, Budget(limits), adapters=adapters, root=root)


# -- role enforcement -------------------------------------------------------


@pytest.mark.parametrize(
    ("family", "role"),
    [("claude", "implement"), ("claude", "review"), ("codex", "advice")],
)
def test_role_split_rejects_crossed_roles(family: str, role: str) -> None:
    with pytest.raises(RoutingDenied) as exc:
        enforce_role(family, role)
    assert exc.value.status == "blocked"
    assert "may not take" in exc.value.reason


@pytest.mark.parametrize(
    ("family", "role"),
    [("claude", "advice"), ("codex", "implement"), ("codex", "review")],
)
def test_role_split_allows_the_intended_roles(family: str, role: str) -> None:
    enforce_role(family, role)
    assert role in ROLE_ALLOWLIST[family]


def test_gateway_blocks_claude_implementation_before_any_adapter(git_repo: Path) -> None:
    adapter = RecordingAdapter(files={"src/x.py": "x = 1\n"})
    gw = gateway(git_repo, {"claude": adapter})
    result = gw.run(envelope(family="claude", label="opus", effort="medium"), "write it")

    assert result.status == Status.BLOCKED
    assert adapter.timeouts == []
    assert "may not take the implement role" in result.limitations[0]


def test_gateway_blocks_codex_advice_before_any_adapter(git_repo: Path) -> None:
    adapter = RecordingAdapter(text="advice")
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(envelope(role=Role.ADVICE), "what should I do")

    assert result.status == Status.BLOCKED
    assert adapter.timeouts == []


def test_advice_that_writes_to_the_repo_is_blocked(git_repo: Path) -> None:
    class WritingAdapter:
        def run(self, envelope, route, prompt, timeout, workdir=None):  # type: ignore[no-untyped-def]
            (workdir / "oops.txt").write_text("touched\n", encoding="utf-8")
            return AdapterOutput(text="advice")

    gw = gateway(git_repo, {"claude": WritingAdapter()})
    result = gw.run(
        envelope(family="claude", label="opus", effort="medium", role=Role.ADVICE), "advise"
    )

    assert result.status == Status.BLOCKED
    assert "oops.txt" in result.limitations[0]


def test_claude_invocation_is_one_turn_without_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    class Done:
        returncode = 0
        stdout = '{"result": "text", "usage": {}}'
        stderr = ""

    def fake_run(cmd: list[str], **kwargs: Any) -> Done:
        captured["cmd"] = cmd
        return Done()

    monkeypatch.setattr("vsw.coding_agent_gateway.shutil.which", lambda name: "/bin/claude")
    monkeypatch.setattr("vsw.coding_agent_gateway.subprocess.run", fake_run)

    ClaudeCliAdapter(Path(".")).run(
        envelope(family="claude", label="opus", effort="medium", role=Role.ADVICE),
        Route("claude", "opus", "medium", "opus"),
        "advise",
        30,
    )
    cmd = captured["cmd"]
    assert "--max-turns" in cmd and cmd[cmd.index("--max-turns") + 1] == "1"
    assert "--tools" in cmd and cmd[cmd.index("--tools") + 1] == ""


def test_codex_review_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, list[str]] = {}

    class Done:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd: list[str], **kwargs: Any) -> Done:
        captured["cmd"] = cmd
        return Done()

    monkeypatch.setattr("vsw.coding_agent_gateway.shutil.which", lambda name: "/bin/codex")
    monkeypatch.setattr("vsw.coding_agent_gateway.subprocess.run", fake_run)

    CodexCliAdapter(Path(".")).run(
        envelope(role=Role.REVIEW),
        Route("codex", "gpt-6.1-sol", "high", "gpt-6.1-sol"),
        "review",
        30,
    )
    cmd = captured["cmd"]
    assert "--sandbox" in cmd and cmd[cmd.index("--sandbox") + 1] == "read-only"


# -- timeouts ---------------------------------------------------------------


def test_implementation_gets_the_longer_default_window() -> None:
    budget = Budget(LIMITS)
    assert budget.call_timeout(implementation=True) == LIMITS.implementation_timeout_seconds
    assert budget.call_timeout() == LIMITS.per_call_timeout_seconds
    assert LIMITS.implementation_timeout_seconds == 300.0
    assert LIMITS.per_call_timeout_seconds == 120.0


def test_requested_timeout_is_kept_when_shorter_and_capped_when_longer() -> None:
    budget = Budget(LIMITS)
    assert budget.call_timeout(60, implementation=True) == 60
    assert budget.call_timeout(9999, implementation=True) == LIMITS.implementation_timeout_seconds
    assert budget.call_timeout(9999) == LIMITS.per_call_timeout_seconds


def test_implementation_timeout_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VSW_IMPLEMENTATION_TIMEOUT", "420")
    limits = load_limits()
    assert limits.implementation_timeout_seconds == 420
    assert Budget(limits).call_timeout(implementation=True) == 420


def test_remaining_wall_clock_caps_the_timeout() -> None:
    budget = Budget(Limits(max_wall_seconds_per_run=30))
    budget.started -= 24
    assert budget.call_timeout(implementation=True) == pytest.approx(6, abs=1.0)


def test_gateway_passes_the_role_aware_timeout(git_repo: Path) -> None:
    adapter = RecordingAdapter(files={"src/x.py": "x = 1\n"})
    gw = gateway(git_repo, {"codex": adapter})
    gw.run(envelope(timeout_s=9999), "implement")

    assert adapter.timeouts == [LIMITS.implementation_timeout_seconds]


# -- changed-file boundaries ------------------------------------------------


def test_reject_outside_paths() -> None:
    permitted = ["src/**", "tests/test_*.py"]
    assert reject_outside_paths(["src/vsw/a.py", "tests/test_a.py"], permitted) == []
    assert reject_outside_paths(["src/a.py", "secrets.txt"], permitted) == ["secrets.txt"]
    assert reject_outside_paths(["/etc/passwd"], permitted) == ["/etc/passwd"]
    assert reject_outside_paths(["src/../../etc/passwd"], permitted) == ["src/../../etc/passwd"]


def test_out_of_bounds_change_blocks_and_never_integrates(git_repo: Path) -> None:
    adapter = RecordingAdapter(
        files={"src/ok.py": "VALUE = 1\n", "secrets.txt": "token\n", "test_ok.py": "x"}
    )
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(
        envelope(permitted_paths=["src/**"], pytest_paths=["test_ok.py"]),
        "implement",
    )

    assert result.status == Status.BLOCKED
    assert "secrets.txt" in result.limitations[0]
    assert "test_ok.py" in result.limitations[0]
    assert result.integrated is False
    assert result.patch_path is not None  # the diff is still captured for review
    assert not (git_repo / "secrets.txt").exists()
    assert not (git_repo / "src" / "ok.py").exists()
    assert result.tests == {}


def test_in_bounds_change_is_applied_only_after_approval(git_repo: Path) -> None:
    adapter = RecordingAdapter(files={"src/ok.py": "VALUE = 1\n"})
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(envelope(permitted_paths=["src/**"]), "implement")

    assert result.status == Status.COMPLETED
    assert result.changed_files == ["src/ok.py"]
    assert result.diff_sha256
    assert result.integrated is False
    assert not (git_repo / "src" / "ok.py").exists()

    approved = gw.integrate(result, "APPROVED", result.diff_sha256)
    assert approved.integrated is True
    assert (git_repo / "src" / "ok.py").read_text(encoding="utf-8") == "VALUE = 1\n"


def test_in_bounds_change_is_not_applied_without_integrate(git_repo: Path) -> None:
    adapter = RecordingAdapter(files={"src/ok.py": "VALUE = 1\n"})
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(envelope(permitted_paths=["src/**"]), "implement")

    assert result.status == Status.COMPLETED
    assert result.integrated is False
    assert not (git_repo / "src" / "ok.py").exists()
    assert Path(result.patch_path or "").exists()


def test_integration_requires_the_reviewed_digest(git_repo: Path) -> None:
    adapter = RecordingAdapter(files={"src/ok.py": "VALUE = 1\n"})
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(envelope(permitted_paths=["src/**"]), "implement")

    blocked = gw.integrate(result, "APPROVED", "0" * 64)
    assert blocked.status is Status.BLOCKED
    assert blocked.integrated is False
    assert "does not match the captured diff" in blocked.limitations[-1]
    assert not (git_repo / "src" / "ok.py").exists()


def test_integration_requires_an_approved_verdict(git_repo: Path) -> None:
    adapter = RecordingAdapter(files={"src/ok.py": "VALUE = 1\n"})
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(envelope(permitted_paths=["src/**"]), "implement")

    for verdict in ("CHANGES_REQUESTED", "INCONCLUSIVE", ""):
        blocked = gw.integrate(result, verdict, result.diff_sha256)
        assert blocked.integrated is False
        assert "not APPROVED" in blocked.limitations[-1]
    assert not (git_repo / "src" / "ok.py").exists()


def test_integration_refuses_a_patch_changed_after_review(git_repo: Path) -> None:
    adapter = RecordingAdapter(files={"src/ok.py": "VALUE = 1\n"})
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(envelope(permitted_paths=["src/**"]), "implement")
    patch = Path(result.patch_path or "")
    patch.write_text(patch.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")

    blocked = gw.integrate(result, "APPROVED", result.diff_sha256)
    assert blocked.integrated is False
    assert "does not match the reviewed digest" in blocked.limitations[-1]
    assert not (git_repo / "src" / "ok.py").exists()


def test_failing_tests_fail_the_implementation_and_block_integration(git_repo: Path) -> None:
    adapter = RecordingAdapter(
        files={
            "src/ok.py": "VALUE = 1\n",
            "test_ok.py": "def test_fails():\n    assert False\n",
        }
    )
    gw = gateway(git_repo, {"codex": adapter})
    result = gw.run(
        envelope(permitted_paths=["src/**", "test_ok.py"], pytest_paths=["test_ok.py"]),
        "implement",
    )

    assert result.status == Status.FAILED
    assert result.tests["ok"] is False
    assert "pytest failed" in result.limitations[0]

    blocked = gw.integrate(result, "APPROVED", result.diff_sha256)
    assert blocked.integrated is False
    assert "only a completed implementation" in blocked.limitations[-1]
    assert not (git_repo / "src" / "ok.py").exists()


def test_patch_outside_runs_is_refused(git_repo: Path) -> None:
    outside = git_repo.parent / "outside.patch"
    outside.write_text("diff --git a/x b/x\n", encoding="utf-8")
    import hashlib

    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    outcome = apply_reviewed_patch(git_repo, str(outside), digest, "APPROVED", True)
    assert outcome["integrated"] is False
    assert "not stored under runs/" in outcome["reason"]
