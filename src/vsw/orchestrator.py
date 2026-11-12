"""Orchestration: the M0 mock demo and the M1 observation pipeline."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .adapters.base import Adapter, AdapterUnavailable
from .adapters.browser import BrowserAdapter
from .adapters.passive_http import PassiveHttpAdapter
from .budget import Budget
from .config import load_limits, repo_root
from .domain import Coverage, Engagement, Finding, FindingState, Severity
from .evidence import EvidenceStore, redact_text
from .model_gateway import MockModelGateway
from .policy import RoutingDenied, resolve_build_route
from .reporting import write_observation_artifacts
from .runtime import CoverageLedger
from .scope import ScopeError, ScopeGuard, load_engagement
from .smoke import run_smoke
from .util import utc_now

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
    run_id = time.strftime("demo-%Y%m%d-%H%M%S", time.gmtime())
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
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
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
        for evidence_id in finding.evidence_ids:
            if evidence_id not in existing.evidence_ids:
                existing.evidence_ids.append(evidence_id)
        for limitation in finding.limitations:
            if limitation not in existing.limitations:
                existing.limitations.append(limitation)
        # Keep the most severe reading and the strongest state when the same
        # check fires from several endpoints.
        if SEVERITY_ORDER.get(finding.severity, 9) < SEVERITY_ORDER.get(existing.severity, 9):
            existing.severity = finding.severity
        if STATE_ORDER.get(finding.state, 9) < STATE_ORDER.get(existing.state, 9):
            existing.state = finding.state
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
) -> dict[str, Any]:
    """Inspect a scoped target, capture hashed evidence, write a report."""
    root = root or repo_root()
    engagement: Engagement = load_engagement(manifest_path)
    guard = ScopeGuard(engagement)

    if target is None:
        origin = engagement.origins[0].rstrip("/")
        prefix = engagement.path_prefixes[0] if engagement.path_prefixes else "/"
        target = origin + (prefix if prefix.startswith("/") else "/" + prefix)
    guard.check(target, "GET", reserve=False)

    run_id = time.strftime("obs-%Y%m%d-%H%M%S", time.gmtime())
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    store = EvidenceStore(run_dir)
    limits = load_limits(root)
    budget = Budget(limits)
    started = utc_now()

    seeds = [target]
    adapters: list[Adapter] = [
        PassiveHttpAdapter(guard, store, engagement),
    ]
    if use_browser:
        adapters.append(BrowserAdapter(guard, store, engagement))

    findings: list[Finding] = []
    adapter_reports: list[dict[str, Any]] = []
    coverage = Coverage(
        targets_planned=[redact_text(item) for item in seeds],
        request_limit=engagement.max_requests,
    )

    for adapter in adapters:
        adapter_seeds = list(seeds)
        if adapter.name == "browser" and coverage.targets_visited:
            adapter_seeds = coverage.targets_visited[:5]
        plan = adapter.plan(adapter_seeds)
        entry: dict[str, Any] = {
            "adapter": plan.adapter,
            "status": "completed",
            "requests": 0,
            "duration_s": 0.0,
            "capabilities": sorted(adapter.capabilities()),
            "note": "",
        }
        begin = time.monotonic()
        try:
            adapter.validate_config()
            if not engagement.mutation_allowed and plan.mutations:
                raise AdapterUnavailable("mutations are not approved for this engagement")
            records = adapter.execute(plan)
            if adapter.cancelled:
                entry["status"] = "cancelled"
            local_findings = adapter.normalize(records)
            findings.extend(local_findings)
            entry["requests"] = len([r for r in records if r.kind != "blocked"])
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
            failures = list(getattr(adapter, "failures", []) or [])
            if failures and entry["status"] == "completed":
                entry["status"] = "partial" if entry["requests"] else "failed"
                entry["note"] = "; ".join(failures[:3])
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
    findings = _dedupe(findings)
    integrity = store.verify()
    # If any capture or index is corrupt, none of its links can substantiate
    # reproduction or negative coverage. Preserve the integrity failure, but
    # keep unverified records out of every exported view.
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
    elif coverage.stop_reason or incomplete or any(
        item["status"] != "completed" for item in adapter_reports
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
