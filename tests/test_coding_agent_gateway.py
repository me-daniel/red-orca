from pathlib import Path

from vsw.budget import Budget
from vsw.coding_agent_gateway import (
    AdapterError,
    AdapterOutput,
    CodingAgentGateway,
    MockAdapter,
)
from vsw.config import Limits
from vsw.domain import Phase, Role, Status, TaskEnvelope

LIMITS = Limits()

FILES = {"src/vsw/ok.py": "VALUE = 1\n"}


def envelope(**overrides):
    data = {
        "id": "t1",
        "purpose": "implement",
        "family": "codex",
        "label": "gpt-6.1-sol",
        "effort": "high",
        "role": Role.IMPLEMENT,
        "budget_usd": 0.5,
        "permitted_paths": ["src/**"],
    }
    data.update(overrides)
    return TaskEnvelope(**data)


def gateway(root: Path, output=None, files=None):
    out = output or AdapterOutput(text="done")
    budget = Budget(LIMITS)
    adapters = {
        "claude": MockAdapter(lambda env, prompt: out),
        "codex": MockAdapter(lambda env, prompt: out, files=FILES if files is None else files),
    }
    return CodingAgentGateway(LIMITS, budget, adapters=adapters, root=root), budget


def test_completed_result_records_actual_model(git_repo):
    gw, budget = gateway(git_repo)
    result = gw.run(envelope(), "do it")
    assert result.status == Status.COMPLETED
    assert result.model_actual == "codex:gpt-6.1-sol"
    assert result.effort_actual == "high"
    assert result.changed_files == ["src/vsw/ok.py"]
    assert budget.calls == 1


def test_implementation_runs_in_a_disposable_worktree(git_repo):
    gw, _ = gateway(git_repo)
    result = gw.run(envelope(), "do it")
    assert result.status == Status.COMPLETED
    # Captured, not applied: the user's tree is untouched until integration.
    assert not (git_repo / "src" / "vsw" / "ok.py").exists()
    assert result.patch_path and Path(result.patch_path).exists()


def test_assessment_phase_is_blocked(git_repo):
    gw, _ = gateway(git_repo)
    result = gw.run(envelope(phase=Phase.ASSESSMENT), "do it")
    assert result.status == Status.BLOCKED


def test_over_budget_task_is_blocked(git_repo):
    gw, _ = gateway(git_repo)
    result = gw.run(envelope(budget_usd=0.9), "do it")
    assert result.status == Status.BLOCKED


def test_cyber_model_is_blocked_before_adapter_runs(git_repo):
    gw, budget = gateway(git_repo)
    result = gw.run(envelope(family="codex", label="gpt-6-sol", effort="max"), "do it")
    assert result.status == Status.BLOCKED
    assert budget.calls == 0


def test_adapter_error_is_failed_not_completed(git_repo):
    def boom(env, prompt):
        raise AdapterError("timeout after 1s")

    budget = Budget(LIMITS)
    gw = CodingAgentGateway(LIMITS, budget, adapters={"codex": MockAdapter(boom)}, root=git_repo)
    result = gw.run(envelope(), "do it")
    assert result.status == Status.FAILED
    assert "timeout" in result.limitations[0]


def test_empty_advice_output_is_failed(git_repo):
    gw, _ = gateway(git_repo, AdapterOutput(text="   "))
    result = gw.run(
        envelope(family="claude", label="opus", effort="medium", role=Role.ADVICE), "do it"
    )
    assert result.status == Status.FAILED


def test_oversized_prompt_is_blocked_before_adapter_runs(git_repo):
    gw, budget = gateway(git_repo)
    result = gw.run(envelope(), "x" * (LIMITS.max_prompt_chars + 1))
    assert result.status == Status.BLOCKED
    assert budget.calls == 0
