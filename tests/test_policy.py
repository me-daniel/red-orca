import unittest

import pytest

from vsw.budget import Budget, BudgetExceeded
from vsw.config import Limits
from vsw.policy import RoutingDenied, resolve_build_route, runtime_route

LIMITS = Limits()


def test_allowed_routes():
    for family, label, effort in (
        ("claude", "opus", "medium"),
        ("claude", "sonnet", "high"),
        ("codex", "gpt-6.1-sol", "high"),
    ):
        route = resolve_build_route(family, label, effort, LIMITS, 0.5)
        assert route.key == f"{family}:{label}:{effort}"


def test_cyber_only_models_are_blocked_at_build():
    with pytest.raises(RoutingDenied) as exc:
        resolve_build_route("codex", "gpt-6-sol", "max", LIMITS, 0.5)
    assert exc.value.status == "blocked"
    assert "assessment" in exc.value.reason

    with pytest.raises(RoutingDenied) as exc:
        resolve_build_route("codex", "luna", "max", LIMITS, 0.5)
    assert exc.value.status == "blocked"


def test_unsupported_effort_returns_unavailable():
    with pytest.raises(RoutingDenied) as exc:
        resolve_build_route("claude", "sonnet", "medium", LIMITS, 0.5)
    assert exc.value.status == "unavailable"

    with pytest.raises(RoutingDenied) as exc:
        resolve_build_route("claude", "sonnet", "low", LIMITS, 0.5)
    assert exc.value.status == "blocked"


def test_opus_high_requires_escalation_reason():
    with pytest.raises(RoutingDenied) as exc:
        resolve_build_route("claude", "opus", "high", LIMITS, 0.5)
    assert exc.value.status == "blocked"
    assert "escalation reason" in exc.value.reason


def test_opus_high_requires_budgeted_escalation():
    with pytest.raises(RoutingDenied) as exc:
        resolve_build_route("claude", "opus", "high", LIMITS, 2.0, escalation_reason="stuck")
    assert exc.value.status == "blocked"
    assert "unbudgeted" in exc.value.reason

    route = resolve_build_route("claude", "opus", "high", LIMITS, 0.9, escalation_reason="stuck")
    assert route.escalated


def test_task_budget_cap():
    with pytest.raises(RoutingDenied) as exc:
        resolve_build_route("claude", "sonnet", "high", LIMITS, 0.6)
    assert exc.value.status == "blocked"
    assert "exceeds" in exc.value.reason


def test_runtime_cyber_routes_are_disabled():
    with pytest.raises(RoutingDenied) as exc:
        runtime_route("evidence_review")
    assert exc.value.status == "blocked"


def test_budget_reset_clock_keeps_calls_and_spend():
    import time as _time

    budget = Budget(Limits(max_wall_seconds_per_run=1, max_delegate_calls_per_run=3))
    budget.begin_call("a")
    budget.record(0.25)
    budget.started = _time.monotonic() - 3600
    with pytest.raises(BudgetExceeded):
        budget.begin_call("a")
    budget.reset_clock()
    budget.begin_call("a")
    assert budget.calls == 2
    assert budget.spent_usd == 0.25
    assert budget.remaining_seconds() > 0


def test_budget_call_limit():
    budget = Budget(Limits(max_delegate_calls_per_run=1))
    budget.begin_call("claude:sonnet:high")
    with pytest.raises(BudgetExceeded):
        budget.begin_call("claude:sonnet:high")


if __name__ == "__main__":
    unittest.main()
