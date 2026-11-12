"""Build-time routing policy.

The allowlist is deliberately small and explicit. Unsupported combinations
return `unavailable`; forbidden combinations return `blocked`. There is no
silent substitution or downgrade.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Limits


class RoutingDenied(RuntimeError):
    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class Route:
    family: str
    label: str
    effort: str
    cli_model: str
    escalated: bool = False

    @property
    def key(self) -> str:
        return f"{self.family}:{self.label}:{self.effort}"


BUILD_ROUTES: dict[tuple[str, str, str], str] = {
    ("claude", "opus", "medium"): "opus",
    ("claude", "sonnet", "high"): "sonnet",
    ("claude", "opus", "high"): "opus",
    ("codex", "gpt-6.1-sol", "high"): "gpt-6.1-sol",
}

ESCALATION_ROUTES = {("claude", "opus", "high")}

CYBER_ONLY_LABELS = {"gpt-6-sol", "gpt-6-luna", "luna", "luna-max", "sol-max"}
DISALLOWED_BUILD_LABELS = {"terra", "haiku", "gpt-6.1-terra"}
DISALLOWED_BUILD_EFFORTS = {"low", "xhigh", "max"}


def resolve_build_route(
    family: str,
    label: str,
    effort: str,
    limits: Limits,
    budget_usd: float,
    escalation_reason: str | None = None,
) -> Route:
    family = family.strip().lower()
    label = label.strip().lower()
    effort = effort.strip().lower()

    if family not in {"claude", "codex"}:
        raise RoutingDenied("unavailable", f"unknown delegate family: {family}")
    if label in CYBER_ONLY_LABELS:
        raise RoutingDenied("blocked", f"{label} is reserved for later assessment runs, not build")
    if label in DISALLOWED_BUILD_LABELS or effort in DISALLOWED_BUILD_EFFORTS:
        raise RoutingDenied(
            "blocked", f"{family}:{label}:{effort} is not an allowlisted build route"
        )

    key = (family, label, effort)
    if key not in BUILD_ROUTES:
        raise RoutingDenied(
            "unavailable", f"{family}:{label}:{effort} is not a configured build route"
        )

    if budget_usd <= 0:
        raise RoutingDenied("blocked", "task budget must be positive")

    escalated = key in ESCALATION_ROUTES
    if escalated:
        if not escalation_reason or not escalation_reason.strip():
            raise RoutingDenied("blocked", "Opus High requires a named escalation reason")
        if budget_usd > limits.max_escalation_usd:
            raise RoutingDenied(
                "blocked",
                f"unbudgeted escalation: ${budget_usd:.2f} > ${limits.max_escalation_usd:.2f}",
            )
    elif budget_usd > limits.max_task_budget_usd:
        raise RoutingDenied(
            "blocked",
            f"task budget ${budget_usd:.2f} exceeds ${limits.max_task_budget_usd:.2f}",
        )

    return Route(
        family=family,
        label=label,
        effort=effort,
        cli_model=BUILD_ROUTES[key],
        escalated=escalated,
    )


# Assessment-time roles are defined here but disabled during build. M4 enables
# them behind an explicit opt-in; MODEL_ROUTING.md keeps them out of build work.
RUNTIME_ROLES: dict[str, dict[str, object]] = {
    "planning": {"model": "deepseek-v4.1-flash", "effort": "high", "enabled": False},
    "triage": {"model": "glm-5.3-flash", "effort": "high", "enabled": False},
    "evidence_review": {"model": "gpt-6-sol", "effort": "max", "enabled": False},
    "independent_review": {"model": "gpt-6-luna", "effort": "max", "enabled": False},
}


def runtime_route(role: str, opt_in: bool = False) -> dict[str, object]:
    if role not in RUNTIME_ROLES:
        raise RoutingDenied("unavailable", f"unknown runtime role: {role}")
    route = dict(RUNTIME_ROLES[role])
    if not opt_in or not route["enabled"]:
        raise RoutingDenied("blocked", f"runtime role {role} is disabled until explicitly enabled")
    return route
