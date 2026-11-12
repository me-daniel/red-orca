"""Lean multi-agent assessment: plan, bounded observation, advisory triage.

The planner and triager only ever propose. Scope, adapters, evidence, and report
state stay deterministic. A model cannot expand the engagement or execute a
shell command here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, Field, ValidationError

from .budget import Budget, BudgetExceeded
from .config import Limits, load_limits, repo_root
from .domain import Confidence, Engagement, Severity
from .evidence import redact_text, redact_value
from .model_gateway import (
    ModelConfig,
    ModelGateway,
    ModelResponse,
    ProviderUnavailable,
    default_model_config_path,
    gateway_for_route,
    load_model_config,
)
from .orchestrator import run_observation
from .scope import ScopeError, ScopeGuard, load_engagement
from .util import new_run_dir

MAX_PLAN_SEEDS = 3
MAX_FOCUS_ITEMS = 5
ALLOWED_CHECKS = ("passive-http", "browser")
_FENCED = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL | re.IGNORECASE)
AssessmentMode = Literal["mock", "live"]


class AssessmentError(RuntimeError):
    pass


class AssessmentPlan(BaseModel):
    focus: list[str] = Field(default_factory=list)
    seeds: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    notes: str = ""


class TriageItem(BaseModel):
    finding_id: str
    assessment: Literal["supported", "needs_evidence", "false_positive"]
    severity: Severity | None = None
    confidence: Confidence | None = None
    reason: str = ""
    follow_up: list[str] = Field(default_factory=list)


class AssessmentTriage(BaseModel):
    items: list[TriageItem] = Field(default_factory=list)
    summary: str = ""


@dataclass
class ModelCall:
    role: str
    route: str
    effort: str
    prompt_chars: int
    response: ModelResponse | None = None
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "role": self.role,
            "route": self.route,
            "effort": self.effort,
            "prompt_chars": self.prompt_chars,
            "error": self.error,
        }
        if self.response is not None:
            data.update(
                {
                    "model": self.response.model,
                    "finish_reason": self.response.finish_reason,
                    "latency_s": self.response.latency_s,
                    "usage": self.response.usage,
                    "cost_usd": self.response.cost_usd,
                    "cost_measured": self.response.cost_measured,
                    "billing_source": self.response.billing_source,
                    "allowance_usd": self.response.allowance_usd,
                    "output_chars": len(self.response.text),
                }
            )
        return data


def _json_object(text: str) -> dict[str, Any]:
    candidate = text.strip()
    fenced = _FENCED.match(candidate)
    if fenced is not None:
        candidate = fenced.group(1).strip()
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start < 0 or end <= start:
        raise AssessmentError("model response did not contain a JSON object")
    try:
        value = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError as exc:
        raise AssessmentError(f"model response was not valid JSON: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise AssessmentError("model response JSON was not an object")
    return value


def _default_target(engagement: Engagement) -> str:
    origin = engagement.origins[0].rstrip("/")
    prefix = engagement.path_prefixes[0] if engagement.path_prefixes else "/"
    return origin + (prefix if prefix.startswith("/") else "/" + prefix)


def _normalise_seed(seed: str, target: str) -> str:
    value = seed.strip()
    if not value:
        return ""
    if not urlsplit(value).scheme:
        value = urljoin(target, value)
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    return value


def _validate_plan(
    plan: AssessmentPlan,
    guard: ScopeGuard,
    target: str,
    use_browser: bool,
) -> tuple[AssessmentPlan, list[dict[str, str]]]:
    rejected: list[dict[str, str]] = []
    seeds: list[str] = []
    for raw in plan.seeds[: MAX_PLAN_SEEDS * 2]:
        if "<redacted>" in raw.lower():
            rejected.append({"seed": raw[:300], "reason": "seed contains redacted text"})
            continue
        seed = _normalise_seed(raw, target)
        if not seed:
            rejected.append({"seed": raw[:300], "reason": "not an absolute http(s) URL"})
            continue
        try:
            guard.check(seed, "GET", reserve=False)
        except ScopeError as exc:
            rejected.append({"seed": seed[:300], "reason": str(exc)[:300]})
            continue
        if seed not in seeds:
            seeds.append(seed)
        if len(seeds) >= MAX_PLAN_SEEDS:
            break
    if not seeds:
        seeds = [target]
    seeds = [target, *[seed for seed in seeds if seed != target]][:MAX_PLAN_SEEDS]

    checks = [item.strip().lower() for item in plan.checks if item.strip().lower() in ALLOWED_CHECKS]
    if not checks:
        checks = ["passive-http", "browser"] if use_browser else ["passive-http"]
    if not use_browser:
        checks = [item for item in checks if item != "browser"] or ["passive-http"]
    if "passive-http" not in checks:
        checks.insert(0, "passive-http")

    focus = [redact_text(item.strip())[:200] for item in plan.focus[:MAX_FOCUS_ITEMS] if item.strip()]
    return (
        AssessmentPlan(
            focus=focus,
            seeds=seeds,
            checks=list(dict.fromkeys(checks)),
            notes=redact_text(plan.notes)[:1000],
        ),
        rejected,
    )


def _mock_plan(target: str, use_browser: bool) -> AssessmentPlan:
    checks = ["passive-http"] + (["browser"] if use_browser else [])
    return AssessmentPlan(
        focus=["headers", "cookies", "reflection", "subresources"],
        seeds=[target],
        checks=checks,
        notes="Deterministic mock plan; no model call.",
    )


def _enum_value(kind: Any, value: object) -> Any:
    try:
        return kind(str(value))
    except (TypeError, ValueError):
        return None


def _mock_triage(findings: list[dict[str, Any]]) -> AssessmentTriage:
    items: list[TriageItem] = []
    for finding in findings:
        state = str(finding.get("state", ""))
        verified = bool(finding.get("reproduction_verified"))
        if state == "validated" and verified:
            assessment: Literal["supported", "needs_evidence", "false_positive"] = "supported"
            reason = "Validated finding with a verified captured reproduction."
        elif state in {"observed", "suspected", "validated"}:
            assessment = "needs_evidence"
            reason = "Captured evidence exists, but it does not yet support validation."
        else:
            assessment = "needs_evidence"
            reason = "Finding is inconclusive; re-test before reporting it as confirmed."
        items.append(
            TriageItem(
                finding_id=str(finding.get("id", "")),
                assessment=assessment,
                severity=_enum_value(Severity, finding.get("severity")),
                confidence=_enum_value(Confidence, finding.get("confidence")),
                reason=reason,
            )
        )
    return AssessmentTriage(
        items=items,
        summary=f"{len(items)} finding(s) reviewed by the deterministic mock triager.",
    )


def _plan_prompt(engagement: Engagement, target: str) -> str:
    return f"""You are the planning agent in a bounded, authorized web assessment.

Engagement:
- id: {engagement.id}
- profile: {engagement.profile.value}
- origins: {", ".join(engagement.origins)}
- methods: {", ".join(engagement.methods)}
- path prefixes: {", ".join(engagement.path_prefixes)}
- exclusions: {", ".join(engagement.exclude_paths) or "none"}
- request limit: {engagement.max_requests}, rate limit: {engagement.max_rps}/s
- default target: {target}

You may only select paths to observe with the registered adapters. You cannot
run shell commands, submit forms, send payloads, change methods, or expand scope.
The only checks are: passive-http, browser.

Return ONLY a JSON object:
{{
  "focus": ["short priority areas, at most 5"],
  "seeds": ["absolute in-scope http(s) URLs, at most 3"],
  "checks": ["passive-http", "browser"],
  "notes": "one short paragraph"
}}
"""


def _triage_prompt(plan: AssessmentPlan, findings: list[dict[str, Any]], coverage: dict[str, Any]) -> str:
    packet = []
    for finding in findings:
        packet.append(
            {
                "id": finding.get("id"),
                "title": finding.get("title"),
                "endpoint": finding.get("endpoint"),
                "check_id": finding.get("check_id"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "state": finding.get("state"),
                "evidence_ids": finding.get("evidence_ids", []),
                "summary": redact_text(str(finding.get("summary", "")))[:500],
                "detail": redact_text(str(finding.get("detail", "")))[:1200],
                "limitations": finding.get("limitations", []),
                "reproduction_verified": finding.get("reproduction_verified", False),
            }
        )
    return f"""You are the independent triage agent in a bounded, authorized web assessment.

Planner focus: {", ".join(plan.focus) or "none"}
Planner notes: {plan.notes or "none"}
Coverage: {json.dumps(coverage, ensure_ascii=False)}

Review only these findings:
{json.dumps(packet, ensure_ascii=False, indent=2)}

Rules:
- Do not invent evidence, findings, or severity beyond what the packet supports.
- "supported" only when the packet shows a validated finding with concrete evidence.
- "needs_evidence" when the finding is observed, suspected, inconclusive, or lacks a
  verified reproduction.
- "false_positive" only with a specific reason.
- Triage is advisory. You cannot change findings, scope, or report state.

Return ONLY a JSON object:
{{
  "items": [
    {{
      "finding_id": "F-001",
      "assessment": "supported|needs_evidence|false_positive",
      "severity": "critical|high|medium|low|info|null",
      "confidence": "high|medium|low|null",
      "reason": "short specific reason",
      "follow_up": ["optional bounded follow-up"]
    }}
  ],
  "summary": "one short paragraph"
}}
"""


def _usable_cost(response: ModelResponse) -> float:
    if response.cost_usd > 0:
        return response.cost_usd
    return response.allowance_usd or 0.0


def _call(
    gateway: ModelGateway,
    budget: Budget,
    *,
    role: str,
    route: str,
    effort: str,
    prompt: str,
) -> tuple[ModelResponse | None, ModelCall]:
    try:
        budget.begin_call(f"assessment:{role}")
        response = gateway.complete(prompt, role=role)
        budget.record(_usable_cost(response))
        return response, ModelCall(
            role=role,
            route=route,
            effort=effort,
            prompt_chars=len(prompt),
            response=response,
        )
    except (ProviderUnavailable, BudgetExceeded) as exc:
        return None, ModelCall(
            role=role,
            route=route,
            effort=effort,
            prompt_chars=len(prompt),
            error=str(exc),
        )


def _validate_triage(
    triage: AssessmentTriage, findings: list[dict[str, Any]]
) -> tuple[AssessmentTriage, list[str], list[str]]:
    known = {str(item.get("id")) for item in findings}
    items = [item for item in triage.items if item.finding_id in known]
    seen = {item.finding_id for item in items}
    unknown = sorted({item.finding_id for item in triage.items if item.finding_id not in known})
    missing = sorted(known - seen)
    return triage.model_copy(update={"items": items}), unknown, missing


def _model_config(root: Path) -> ModelConfig:
    return load_model_config(default_model_config_path(root))


def _live_gateway(
    config: ModelConfig, route: str, limits: Limits, evaluate: bool
) -> ModelGateway:
    return gateway_for_route(config, route, limits=limits, allow_disabled=evaluate)


def run_assessment(
    manifest_path: Path,
    target: str | None = None,
    *,
    mode: AssessmentMode = "mock",
    use_browser: bool = True,
    root: Path | None = None,
    plan_route: str = "plan",
    triage_route: str = "triage",
    evaluate: bool = False,
    gateway: ModelGateway | None = None,
) -> dict[str, Any]:
    """Plan, observe, and triage within one approved engagement."""
    if mode not in {"mock", "live"}:
        raise AssessmentError("mode must be 'mock' or 'live'")
    root = root or repo_root()
    engagement = load_engagement(manifest_path)
    guard = ScopeGuard(engagement)
    target = target or _default_target(engagement)
    guard.check(target, "GET", reserve=False)
    limits = load_limits(root)
    budget = Budget(limits)
    run_id, run_dir = new_run_dir(root, "assess")

    calls: list[ModelCall] = []
    plan_errors: list[str] = []
    config: ModelConfig | None = None
    if mode == "live" and gateway is None:
        try:
            config = _model_config(root)
        except ProviderUnavailable as exc:
            plan_errors.append(str(exc))

    if mode == "mock":
        plan = _mock_plan(target, use_browser)
    else:
        plan_prompt = _plan_prompt(engagement, redact_text(target))
        response: ModelResponse | None = None
        if gateway is not None:
            response, call = _call(
                gateway,
                budget,
                role="plan",
                route=plan_route,
                effort="none",
                prompt=plan_prompt,
            )
            calls.append(call)
        elif config is not None:
            try:
                route_config = config.routes[plan_route]
                live = _live_gateway(config, plan_route, limits, evaluate)
                response, call = _call(
                    live,
                    budget,
                    role="plan",
                    route=plan_route,
                    effort=route_config.effort,
                    prompt=plan_prompt,
                )
                calls.append(call)
            except ProviderUnavailable as exc:
                plan_errors.append(str(exc))
        if response is None:
            plan_errors.append("planner unavailable; using the deterministic plan")
            plan = _mock_plan(target, use_browser)
        else:
            try:
                plan = AssessmentPlan.model_validate(_json_object(response.text))
            except (AssessmentError, ValidationError) as exc:
                plan_errors.append(f"planner output rejected: {exc}")
                plan = _mock_plan(target, use_browser)

    plan, rejected = _validate_plan(plan, guard, target, use_browser)
    checks = plan.checks

    observation = run_observation(
        manifest_path,
        target,
        use_browser="browser" in checks,
        root=root,
        targets=plan.seeds,
        run_dir=run_dir,
    )
    findings = observation.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    triage_errors: list[str] = []
    if mode == "mock":
        triage = _mock_triage(findings)
    else:
        triage_prompt = _triage_prompt(
            plan,
            findings,
            {
                "requests_made": observation.get("coverage", {}).get("requests_made", 0),
                "request_limit": observation.get("coverage", {}).get("request_limit", 0),
                "stop_reason": observation.get("coverage", {}).get("stop_reason", ""),
                "status": observation.get("status"),
                "evidence_integrity": observation.get("evidence_integrity", []),
            },
        )
        response = None
        if gateway is not None:
            response, call = _call(
                gateway,
                budget,
                role="triage",
                route=triage_route,
                effort="none",
                prompt=triage_prompt,
            )
            calls.append(call)
        elif config is not None:
            try:
                route_config = config.routes[triage_route]
                live = _live_gateway(config, triage_route, limits, evaluate)
                response, call = _call(
                    live,
                    budget,
                    role="triage",
                    route=triage_route,
                    effort=route_config.effort,
                    prompt=triage_prompt,
                )
                calls.append(call)
            except ProviderUnavailable as exc:
                triage_errors.append(str(exc))
        if response is None:
            triage_errors.append("triager unavailable; using the deterministic triage")
            triage = _mock_triage(findings)
        else:
            try:
                triage = AssessmentTriage.model_validate(_json_object(response.text))
            except (AssessmentError, ValidationError) as exc:
                triage_errors.append(f"triager output rejected: {exc}")
                triage = _mock_triage(findings)

    triage, unknown_ids, unmentioned_ids = _validate_triage(triage, findings)
    if observation.get("status") == "fail":
        status = "fail"
    elif observation.get("status") == "partial" or plan_errors or triage_errors:
        status = "partial"
    else:
        status = "pass"

    payload: dict[str, Any] = {
        "run_id": run_id,
        "mode": mode,
        "evaluation": bool(evaluate and mode == "live"),
        "status": status,
        "observation_status": observation.get("status"),
        "plan": plan.model_dump(mode="json"),
        "plan_rejected_seeds": rejected,
        "plan_errors": plan_errors,
        "triage": triage.model_dump(mode="json"),
        "triage_errors": triage_errors,
        "unknown_finding_ids": unknown_ids,
        "unmentioned_finding_ids": unmentioned_ids,
        "model_calls": [call.as_dict() for call in calls],
        "limits": limits.as_dict(),
        "observation": {
            "run_id": observation.get("run_id"),
            "status": observation.get("status"),
            "findings": len(findings),
            "requests_made": observation.get("coverage", {}).get("requests_made", 0),
            "request_limit": observation.get("coverage", {}).get("request_limit", 0),
            "stop_reason": observation.get("coverage", {}).get("stop_reason", ""),
            "evidence_integrity": observation.get("evidence_integrity", []),
        },
    }
    safe_payload: dict[str, Any] = redact_value(payload)
    assessment_json = run_dir / "assessment.json"
    assessment_md = run_dir / "assessment.md"
    assessment_json.write_text(
        json.dumps(safe_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    assessment_md.write_text(render_assessment_markdown(safe_payload), encoding="utf-8")

    run_record_path = run_dir / "run.json"
    if run_record_path.exists():
        try:
            run_record = json.loads(run_record_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            run_record = {}
        run_record["assessment"] = {
            "status": status,
            "mode": mode,
            "plan_route": plan_route,
            "triage_route": triage_route,
        }
        run_record_path.write_text(
            json.dumps(run_record, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    return {
        **safe_payload,
        "run_dir": str(run_dir),
        "assessment_json": str(assessment_json),
        "assessment_markdown": str(assessment_md),
    }


def _cell(value: object, limit: int = 160) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text.replace("|", "\\|")


def render_assessment_markdown(payload: dict[str, Any]) -> str:
    plan = payload.get("plan", {})
    triage = payload.get("triage", {})
    calls = payload.get("model_calls", [])
    observation = payload.get("observation", {})
    lines = [
        f"# vsw assessment — {_cell(payload.get('run_id', ''), 80)}",
        "",
        f"- Status: **{_cell(payload.get('status', ''), 20)}**",
        f"- Observation: **{_cell(payload.get('observation_status', ''), 20)}**",
        f"- Mode: {_cell(payload.get('mode', ''), 20)}"
        + (" (evaluation route use)" if payload.get("evaluation") else ""),
        "",
        "## Plan",
        "",
        f"- Focus: {', '.join(_cell(item, 80) for item in plan.get('focus', [])) or 'none'}",
        f"- Checks: {', '.join(_cell(item, 40) for item in plan.get('checks', [])) or 'none'}",
        f"- Notes: {_cell(plan.get('notes', ''), 400) or 'none'}",
    ]
    lines += [f"- Seed: `{_cell(seed, 180)}`" for seed in plan.get("seeds", [])]
    for rejected in payload.get("plan_rejected_seeds", []):
        lines.append(
            f"- Rejected seed `{_cell(rejected.get('seed', ''), 160)}`: "
            f"{_cell(rejected.get('reason', ''), 200)}"
        )
    for error in payload.get("plan_errors", []):
        lines.append(f"- Planner error: {_cell(error, 300)}")
    lines += ["", "## Triage", "", "| Finding | Assessment | Severity | Confidence | Reason |", "| --- | --- | --- | --- | --- |"]
    for item in triage.get("items", []):
        lines.append(
            f"| {_cell(item.get('finding_id', ''), 20)} "
            f"| {_cell(item.get('assessment', ''), 30)} "
            f"| {_cell(item.get('severity') or '-', 20)} "
            f"| {_cell(item.get('confidence') or '-', 20)} "
            f"| {_cell(item.get('reason', ''), 240)} |"
        )
    lines += [
        "",
        _cell(triage.get("summary", ""), 1000) or "No triage summary.",
        "",
        f"- Observation findings: {observation.get('findings', 0)}",
        (
            f"- Observation requests: {observation.get('requests_made', 0)} of "
            f"{observation.get('request_limit', 0)}"
        ),
        f"- Observation stop reason: {_cell(observation.get('stop_reason') or 'completed', 120)}",
    ]
    if payload.get("unmentioned_finding_ids"):
        lines.append(
            "- Findings the triager did not mention: "
            + ", ".join(_cell(item, 40) for item in payload["unmentioned_finding_ids"])
        )
    for error in payload.get("triage_errors", []):
        lines.append(f"- Triager error: {_cell(error, 300)}")
    lines += ["", "## Model calls", ""]
    if not calls:
        lines.append("- No model calls in mock mode.")
    else:
        lines += [
            "| Role | Route | Model | Effort | Latency | Cost | Allowance |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for call in calls:
            if call.get("error"):
                lines.append(
                    f"| {_cell(call.get('role'), 20)} | {_cell(call.get('route'), 20)} "
                    f"| unavailable | {_cell(call.get('effort'), 20)} | - | - | - |"
                )
            else:
                lines.append(
                    f"| {_cell(call.get('role'), 20)} "
                    f"| {_cell(call.get('route'), 20)} "
                    f"| {_cell(call.get('model'), 60)} "
                    f"| {_cell(call.get('effort'), 20)} "
                    f"| {call.get('latency_s', 0)}s "
                    f"| ${call.get('cost_usd', 0):.6f} "
                    f"| {call.get('allowance_usd') or '-'} |"
                )
    lines += [
        "",
        "## Limits",
        "",
        "- Triage is advisory. A model did not change finding states, scope, or report state.",
        "- The planner may only select registered adapter seeds inside the approved scope.",
        "- A missing finding or a clean coverage claim is not evidence of safety.",
        "",
    ]
    return "\n".join(lines)
