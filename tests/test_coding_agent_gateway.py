from vsw.budget import Budget
from vsw.coding_agent_gateway import (
    AdapterError,
    AdapterOutput,
    CodingAgentGateway,
    MockAdapter,
)
from vsw.config import Limits
from vsw.domain import Phase, Status, TaskEnvelope

LIMITS = Limits()


def envelope(**overrides):
    data = {
        "id": "t1",
        "purpose": "implement",
        "family": "claude",
        "label": "sonnet",
        "effort": "high",
        "budget_usd": 0.5,
        "timeout_s": 30,
        "permitted_paths": ["src/**"],
    }
    data.update(overrides)
    return TaskEnvelope(**data)


def gateway(output=None, **kwargs):
    out = output or AdapterOutput(text="done")
    budget = Budget(LIMITS)
    return (
        CodingAgentGateway(
            LIMITS,
            budget,
            adapters={
                "claude": MockAdapter(lambda env, prompt: out),
                "codex": MockAdapter(lambda env, prompt: out),
            },
        ),
        budget,
    )


def test_completed_result_records_actual_model():
    gw, budget = gateway()
    result = gw.run(envelope(), "do it")
    assert result.status == Status.COMPLETED
    assert result.model_actual == "claude:sonnet"
    assert result.effort_actual == "high"
    assert budget.calls == 1


def test_forbidden_patch_path_blocks_result():
    gw, _ = gateway(AdapterOutput(text="patch", changed_files=["src/vsw/ok.py", "/etc/passwd"]))
    result = gw.run(envelope(), "do it")
    assert result.status == Status.BLOCKED
    assert "forbidden paths" in result.limitations[0]


def test_path_traversal_is_rejected():
    gw, _ = gateway(AdapterOutput(text="patch", changed_files=["src/../secrets.txt"]))
    result = gw.run(envelope(), "do it")
    assert result.status == Status.BLOCKED


def test_assessment_phase_is_blocked():
    gw, _ = gateway()
    result = gw.run(envelope(phase=Phase.ASSESSMENT), "do it")
    assert result.status == Status.BLOCKED


def test_over_budget_task_is_blocked():
    gw, _ = gateway()
    result = gw.run(envelope(budget_usd=0.9), "do it")
    assert result.status == Status.BLOCKED


def test_cyber_model_is_blocked_before_adapter_runs():
    gw, budget = gateway()
    result = gw.run(envelope(family="codex", label="gpt-6-sol", effort="max"), "do it")
    assert result.status == Status.BLOCKED
    assert budget.calls == 0


def test_adapter_error_is_failed_not_completed():
    def boom(env, prompt):
        raise AdapterError("timeout after 1s")

    budget = Budget(LIMITS)
    gw = CodingAgentGateway(
        LIMITS, budget, adapters={"claude": MockAdapter(boom), "codex": MockAdapter(boom)}
    )
    result = gw.run(envelope(), "do it")
    assert result.status == Status.FAILED
    assert "timeout" in result.limitations[0]


def test_empty_output_is_failed():
    gw, _ = gateway(AdapterOutput(text="   "))
    result = gw.run(envelope(), "do it")
    assert result.status == Status.FAILED
