"""Orchestration: the M0 mock demo and the M1 observation pipeline."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .adapters.base import Adapter, AdapterUnavailable
from .adapters.browser import BrowserAdapter
from .adapters.passive_http import PassiveHttpAdapter
from .adapters.validation import CHECKS, ValidationAdapter
from .budget import Budget
from .config import load_limits, repo_root
from .domain import CheckPlan, Coverage, Engagement, Finding, FindingState, Severity
from .evidence import EvidenceRecord, EvidenceStore, redact_text
from .model_gateway import MockModelGateway
from .policy import RoutingDenied, resolve_build_route
from .reporting import write_observation_artifacts
from .reproduction import redact_reproduction, verify_reproduction
from .runtime import CoverageLedger
from .scope import SAFE_METHODS, ScopeError, ScopeGuard, load_engagement
from .smoke import run_smoke
from .util import new_run_dir, utc_now

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
STATE_ORDER = {
    FindingState.VALIDATED: 0,
    FindingState.SUSPECTED: 1,
    FindingState.OBSERVED: 2,
    FindingState.INCONCLUSIVE: 3,
    FindingState.NOT_REPRODUCED: 4,
    FindingState.FIXED: 5,
}


def run_mock_demo(root: Path | None = None) -> dict[str, Any]:
    root = root or repo_root()
    limits = load_limits(root)
    gateway = MockModelGateway()
    plan = gateway.complete("Plan the M0 mock demo.", "plan")

    policy = []
    for family, label, effort in (
        ("claude", "sonnet", "high"),
        ("codex", "gpt-6.1-sol", "high"),
    ):
        route = resolve_build_route(family, label, effort, limits, limits.max_task_budget_usd)
        policy.append({"route": route.key, "decision": "allowed"})
    for family, label, effort in (
        ("codex", "gpt-6-sol", "max"),
        ("claude", "opus", "high"),
    ):
        try:
            resolve_build_route(family, label, effort, limits, limits.max_task_budget_usd)
        except RoutingDenied as exc:
            policy.append(
                {
                    "route": f"{family}:{label}:{effort}",
                    "decision": exc.status,
                    "reason": exc.reason,
                }
            )

    smoke = run_smoke("mock", root)
    run_id, run_dir = new_run_dir(root, "demo")
    report = {
        "run_id": run_id,
        "stage": "M0",
        "mode": "mock",
        "started": utc_now(),
        "plan": plan.text,
        "policy": policy,
        "smoke": {
            "run_id": smoke["run_id"],
            "status": smoke["status"],
            "checks": smoke["checks"],
        },
        "status": smoke["status"],
    }
    (run_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (run_dir / "report.md").write_text(
        "\n".join(
            [
                f"# M0 mock demo — {run_id}",
                "",
                f"Status: **{report['status']}**",
                "",
                "## Plan",
                "",
                plan.text,
                "",
                "## Policy decisions",
                "",
                *[
                    f"- `{item['route']}`: {item['decision']}"
                    + (f" ({item.get('reason')})" if item.get("reason") else "")
                    for item in policy
                ],
                "",
                "## Smoke",
                "",
                f"- run: `{smoke['run_id']}`",
                f"- status: **{smoke['status']}**",
                *[f"- {c['name']}: {'PASS' if c['ok'] else 'FAIL'}" for c in smoke["checks"]],
                "",
                "This demo uses deterministic mocks. It makes no remote model calls.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    report["run_dir"] = str(run_dir)
    return report


# -- M1: observation -------------------------------------------------------


AGGREGATE_PREFIXES = ("headers.", "cookies.")


def _check_plan(adapter: Adapter, plan: CheckPlan, guard: ScopeGuard) -> None:
    """Refuse an adapter plan that declares work outside its approved envelope."""
    if plan.adapter != adapter.name:
        raise ValueError(f"plan adapter {plan.adapter!r} does not match {adapter.name!r}")
    if not plan.destinations or not plan.methods:
        raise ValueError("plan must declare destinations and methods")
    if plan.estimated_requests < 0:
        raise ValueError("plan estimated_requests cannot be negative")
    if any(method != method.upper() for method in plan.methods):
        raise ValueError("plan methods must be uppercase")
    if any(method not in SAFE_METHODS for method in plan.methods) and not plan.mutations:
        raise ValueError("plan must declare mutations for state-changing methods")
    if plan.mutations and not guard.engagement.mutation_allowed:
        raise AdapterUnavailable("mutations are not approved for this engagement")
    for destination in plan.destinations:
        for method in plan.methods:
            guard.check(destination, method, reserve=False)


def _check_adapter_evidence(
    returned: dict[str, list[EvidenceRecord]],
    attributed: list[tuple[str, Finding]],
    evidence: list[dict[str, Any]],
) -> tuple[list[str], set[str]]:
    """Accept findings only when their adapter returned verified stored captures."""
    by_id = {str(item["id"]): item for item in evidence}
    valid_ids: dict[str, set[str]] = {}
    errors: list[str] = []
    bad_adapters: set[str] = set()
    for name, records in returned.items():
        accepted: set[str] = set()
        for record in records:
            stored = by_id.get(record.id)
            if (
                record.id in accepted
                or stored is None
                or stored.get("source") != name
                or record.record_sha256 != stored.get("record_sha256")
                or record.as_dict()["record_sha256"] != stored.get("record_sha256")
            ):
                errors.append(f"{name}: returned evidence {record.id} is not its verified capture")
                bad_adapters.add(name)
            else:
                accepted.add(record.id)
        valid_ids[name] = accepted
    for name, finding in attributed:
        ids = valid_ids.get(name, set())
        if not finding.evidence_ids or not set(finding.evidence_ids) <= ids:
            errors.append(f"{name}: finding {finding.check_id} lacks verified adapter evidence")
            bad_adapters.add(name)
        if finding.exchange_ids and not all(
            item in ids and by_id[item].get("kind") == "http" for item in finding.exchange_ids
        ):
            errors.append(f"{name}: finding {finding.check_id} cites an unverified exchange")
            bad_adapters.add(name)
        if finding.state == FindingState.VALIDATED:
            detail = finding.reproduction_detail
            check = verify_reproduction(redact_reproduction(detail), by_id) if detail else None
            if (
                detail is None
                or check is None
                or not check.verified
                or any(
                    not set(step.evidence_ids) <= set(finding.evidence_ids) for step in detail.steps
                )
            ):
                errors.append(
                    f"{name}: validated finding {finding.check_id} lacks captured reproduction"
                )
                bad_adapters.add(name)
    return errors, bad_adapters


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Aggregate per-origin checks; keep per-endpoint checks separate."""
    merged: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        endpoint = "" if finding.check_id.startswith(AGGREGATE_PREFIXES) else finding.endpoint
        key = (finding.asset, endpoint, finding.check_id)
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        # Keep the record whose state and severity were actually supported by
        # its own capture and reproduction; merge only references and limits.
        if (
            STATE_ORDER.get(finding.state, 9),
            SEVERITY_ORDER.get(finding.severity, 9),
        ) < (
            STATE_ORDER.get(existing.state, 9),
            SEVERITY_ORDER.get(existing.severity, 9),
        ):
            merged[key] = finding
            existing, finding = finding, existing
        for evidence_id in finding.evidence_ids:
            if evidence_id not in existing.evidence_ids:
                existing.evidence_ids.append(evidence_id)
        for limitation in finding.limitations:
            if limitation not in existing.limitations:
                existing.limitations.append(limitation)
    ordered = sorted(
        merged.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 9),
            STATE_ORDER.get(item.state, 9),
            item.check_id,
            item.asset,
            item.endpoint,
        ),
    )
    for index, finding in enumerate(ordered, start=1):
        finding.id = f"F-{index:03d}"
    return ordered


def run_observation(
    manifest_path: Path,
    target: str | None = None,
    *,
    use_browser: bool = True,
    root: Path | None = None,
    targets: list[str] | None = None,
    run_dir: Path | None = None,
    validation_checks: list[str] | None = None,
) -> dict[str, Any]:
    """Inspect scoped targets, capture hashed evidence, write a report."""
    root = root or repo_root()
    if validation_checks is not None:
        if (
            not validation_checks
            or any(check not in CHECKS for check in validation_checks)
            or len(set(validation_checks)) != len(validation_checks)
        ):
            raise ScopeError("checks must be nonempty, unique registered validation checks")
        if (targets is None and target is None) or (targets is not None and len(targets) != 1):
            raise ScopeError("validation requires exactly one explicit target")
    engagement: Engagement = load_engagement(manifest_path)
    guard = ScopeGuard(engagement)

    if targets is None:
        if target is None:
            origin = engagement.origins[0].rstrip("/")
            prefix = engagement.path_prefixes[0] if engagement.path_prefixes else "/"
            target = origin + (prefix if prefix.startswith("/") else "/" + prefix)
        targets = [target]
    if not targets:
        raise ScopeError("no observation targets")
    for seed in targets:
        guard.check(seed, "GET", reserve=False)
    target = targets[0]

    if run_dir is None:
        run_id, run_dir = new_run_dir(root, "obs")
    else:
        run_dir = run_dir.resolve()
        run_dir.mkdir(parents=True, exist_ok=True)
        run_id = run_dir.name
    store = EvidenceStore(run_dir)
    limits = load_limits(root)
    budget = Budget(limits)
    started = utc_now()

    seeds = list(targets)
    adapters: list[Adapter]
    validation_plan: CheckPlan | None = None
    if validation_checks is not None:
        validation_adapter = ValidationAdapter(guard, store, engagement, validation_checks)
        # Preflight the explicit validation target and every final probe before
        # execution, allowing configuration errors to reach the CLI as blocked.
        validation_plan = validation_adapter.plan(seeds)
        _check_plan(validation_adapter, validation_plan, guard)
        adapters = [validation_adapter]
    else:
        adapters = [PassiveHttpAdapter(guard, store, engagement)]
        if use_browser:
            adapters.append(BrowserAdapter(guard, store, engagement))

    findings: list[Finding] = []
    returned: dict[str, list[EvidenceRecord]] = {}
    attributed: list[tuple[str, Finding]] = []
    adapter_reports: list[dict[str, Any]] = []
    coverage = Coverage(
        targets_planned=[redact_text(item) for item in seeds],
        request_limit=engagement.max_requests,
    )

    for adapter in adapters:
        adapter_seeds = list(seeds)
        if adapter.name == "browser" and coverage.targets_visited:
            adapter_seeds = coverage.targets_visited[:5]
        entry: dict[str, Any] = {
            "adapter": adapter.name,
            "status": "completed",
            "requests": 0,
            "duration_s": 0.0,
            "capabilities": [],
            "note": "",
        }
        begin = time.monotonic()
        try:
            entry["capabilities"] = sorted(adapter.capabilities())
            adapter.validate_config()
            plan = (
                validation_plan
                if adapter.name == "validation" and validation_plan is not None
                else adapter.plan(adapter_seeds)
            )
            _check_plan(adapter, plan, guard)
            records = adapter.execute(plan)
            if not isinstance(records, list) or not all(
                isinstance(record, EvidenceRecord) for record in records
            ):
                raise ValueError("execute must return a list of EvidenceRecord")
            if any(record.kind not in {"http", "browser", "blocked"} for record in records):
                raise ValueError("execute returned an unknown evidence kind")
            returned[adapter.name] = records
            if adapter.cancelled:
                entry["status"] = "cancelled"
            local_findings = adapter.normalize(records)
            if not isinstance(local_findings, list) or not all(
                isinstance(finding, Finding) for finding in local_findings
            ):
                raise ValueError("normalize must return a list of Finding")
            findings.extend(local_findings)
            attributed.extend((adapter.name, finding) for finding in local_findings)
            entry["requests"] = len([r for r in records if r.kind != "blocked"])
            failures = list(getattr(adapter, "failures", []) or [])
            if failures and entry["status"] in {"completed", "partial"}:
                entry["status"] = "partial" if entry["requests"] else "failed"
                entry["note"] = "; ".join(failures[:3])
            if (
                not any(record.kind in {"http", "browser"} for record in records)
                and entry["status"] == "completed"
            ):
                entry["status"] = "partial"
                entry["note"] = "adapter completed without observation captures"
            for record in records:
                if record.truncated:
                    coverage.truncated_pages.append(record.url)
                if record.kind != "blocked" and record.url not in coverage.targets_visited:
                    coverage.targets_visited.append(record.url)
            if adapter.name == "passive-http":
                visited = getattr(adapter, "visited", [])
                for url in visited:
                    safe_url = redact_text(str(url))
                    if safe_url not in coverage.targets_visited:
                        coverage.targets_visited.append(safe_url)
        except AdapterUnavailable as exc:
            entry["status"] = "unavailable"
            entry["note"] = str(exc)
        except ScopeError as exc:
            entry["status"] = "blocked"
            entry["note"] = str(exc)
        except Exception as exc:  # noqa: BLE001 - record and keep the run honest
            entry["status"] = "failed"
            entry["note"] = f"{type(exc).__name__}: {exc}"
        entry["note"] = redact_text(str(entry.get("note") or ""))
        entry["duration_s"] = round(time.monotonic() - begin, 3)
        adapter_reports.append(entry)

    for blocked in guard.blocked:
        store.capture(
            kind="blocked",
            url=str(blocked.get("url", "")),
            source="scope-guard",
            notes={"reason": blocked.get("reason", ""), "kind": blocked.get("kind", "")},
        )
        coverage.skipped.append(
            {
                "url": redact_text(str(blocked.get("url", ""))),
                "reason": str(blocked.get("reason", "")),
            }
        )

    coverage.requests_made = guard.requests
    coverage.stop_reason = guard.stop_reason
    coverage.adapters = adapter_reports
    integrity = store.verify()
    if not integrity:
        link_errors, bad_adapters = _check_adapter_evidence(returned, attributed, store.records())
        integrity.extend(link_errors)
        for entry in adapter_reports:
            if entry["adapter"] in bad_adapters:
                entry["status"] = "failed"
                entry["note"] = "returned evidence or finding links did not verify"
    findings = _dedupe(findings)
    # If any capture or index is corrupt, none of its links can substantiate
    # reproduction or negative coverage. Preserve the integrity failure, but
    # keep unverified records out of every exported view.
    if integrity:
        coverage.targets_visited.clear()
        coverage.truncated_pages.clear()
        for entry in adapter_reports:
            entry["requests"] = 0
    evidence = store.records() if not integrity else []
    ledger = CoverageLedger(store)
    ledger.record_observation(
        target=redact_text(target),
        adapters=adapter_reports,
        evidence=evidence,
        findings=findings,
        stop_reason=coverage.stop_reason,
    )
    coverage.entries = ledger.entries

    finished = utc_now()
    # A run only passes when evidence verifies, at least one adapter ran, and
    # every requested adapter completed. "No findings" from a run where the
    # browser was skipped for https is incomplete coverage, not a clean bill.
    executed = [item for item in adapter_reports if item["status"] in {"completed", "partial"}]
    incomplete = [
        item for item in adapter_reports if item["status"] not in {"completed", "partial"}
    ]
    if integrity or not executed:
        run_status = "fail"
    elif (
        coverage.stop_reason
        or incomplete
        or any(item["status"] != "completed" for item in adapter_reports)
    ):
        run_status = "partial"
    else:
        run_status = "pass"

    payload = write_observation_artifacts(
        run_dir,
        run_id=run_id,
        status=run_status,
        target=target,
        engagement=engagement,
        findings=findings,
        coverage=coverage,
        evidence=evidence,
        adapters=adapter_reports,
        budget=budget.status(),
        evidence_integrity=integrity,
        started=started,
        finished=finished,
    )
    payload["run_dir"] = str(run_dir)
    return payload
