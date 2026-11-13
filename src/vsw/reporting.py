"""Report rendering.

Everything that came from a target is escaped before it reaches Markdown or
JSON. Reports always separate observed facts from unproven inference and
always state what was not tested.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .domain import Coverage, CoverageOutcome, Engagement, Finding, FindingState
from .evidence import redact_text, redact_value
from .reproduction import (
    finding_export,
    redact_export_payload,
    redact_reproduction,
    verify_reproduction,
)
from .scope import manifest_hash

_MD_ACTIVE = str.maketrans(
    {
        "|": "\\|",
        "`": "\\`",
        "[": "\\[",
        "]": "\\]",
        "*": "\\*",
        "_": "\\_",
        "<": "\\<",
        ">": "\\>",
    }
)


def _md(text: object, limit: int = 300) -> str:
    """Escape target-controlled text so it cannot form links, images, or code."""
    value = str(text).replace("\r", " ").replace("\n", " ")
    if len(value) > limit:
        value = value[:limit] + "…[truncated]"
    return value.translate(_MD_ACTIVE)


def _md_block(text: object, limit: int = 4000) -> str:
    return _md(text, limit=limit)


def _md_code(text: object, limit: int = 8000) -> str:
    """Fence target-controlled text so it cannot break out of the code block.

    A fenced block closes only on a run of backticks at least as long as the
    opening fence. Open with one more backtick than the longest run inside the
    content, never fewer than three.
    """
    value = str(text)
    if len(value) > limit:
        value = value[:limit] + "…[truncated]"
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{value}\n{fence}"


def _repro_lines(finding: Finding, records: Mapping[str, dict[str, Any]]) -> list[str]:
    """Prefer captured reproduction over later prose or a rewritten PoC."""
    detail = finding.reproduction_detail
    if detail is not None and (
        detail.entry_point or detail.prerequisites or detail.steps or detail.provenance
    ):
        redacted = redact_reproduction(detail)
        check = verify_reproduction(redacted, records)
        if check.verified:
            lines = ["Reproduction (captured):"]
        else:
            lines = ["Reproduction (unverified):"]
            lines.append(
                "- Links did not verify: "
                + "; ".join(_md(error, 200) for error in check.errors[:3])
            )
        if redacted.provenance:
            lines.append(f"- Origin: {_md(redacted.provenance, 300)}")
        if redacted.entry_point:
            lines.append(f"- Entry point: {_md(redacted.entry_point, 300)}")
        if redacted.prerequisites:
            lines.append("- Prerequisites:")
            lines += [f"  - {_md(item, 300)}" for item in redacted.prerequisites]
        for index, step in enumerate(redacted.steps, start=1):
            summary: list[str] = []
            if step.expected:
                summary.append(f"expected: {_md(step.expected, 300)}")
            if step.proves:
                summary.append(f"proves: {_md(step.proves, 300)}")
            line = f"- Step {index}"
            if summary:
                line += " — " + "; ".join(summary)
            lines.append(line)
            if step.exchange_id:
                lines.append(f"  - Exchange: `{_md(step.exchange_id, 120)}`")
            if step.evidence_ids:
                lines.append(f"  - Evidence: {', '.join(step.evidence_ids)}")
            if step.request:
                lines.append(_md_code(step.request))
            if step.response:
                lines.append("Response:")
                lines.append(_md_code(step.response))
        lines.append("")
        return lines
    if finding.reproduction:
        lines = ["Reproduction:"]
        lines += [f"1. {_md(step, 200)}" for step in finding.reproduction]
        lines.append("")
        return lines
    return []


def render_markdown(
    *,
    run_id: str,
    engagement: dict[str, Any],
    findings: list[Finding],
    coverage: Coverage,
    evidence: list[dict[str, Any]],
    adapters: list[dict[str, Any]],
    budget: dict[str, Any],
    started: str,
    finished: str,
    status: str = "",
    evidence_integrity: list[str] | None = None,
) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.state.value] = counts.get(finding.state.value, 0) + 1
    validated = counts.get(FindingState.VALIDATED.value, 0)
    record_index = {str(item["id"]): item for item in evidence if item.get("id")}

    validation_run = any(item.get("adapter") == "validation" for item in adapters)
    report_kind = "validation" if validation_run else "observation"
    lines: list[str] = [
        f"# vsw {report_kind} report — {_md(run_id, 80)}",
        "",
        f"- Started: {_md(started, 40)}",
        f"- Finished: {_md(finished, 40)}",
    ]
    if status:
        lines.append(f"- Run status: **{_md(status, 20)}**")
    lines += [
        f"- Engagement: `{_md(engagement.get('id', ''), 60)}`",
        f"- Profile: `{_md(engagement.get('profile', ''), 40)}`",
        f"- Manifest hash: `{_md(engagement.get('manifest_sha256', ''), 80)}`",
        f"- Validated findings: **{validated}**",
        "",
        "## Scope and authorization",
        "",
        f"- Owner: {_md(engagement.get('owner', ''), 100)}",
        f"- Approver: {_md(engagement.get('approver', ''), 100)}",
        f"- Authorization reference: {_md(engagement.get('authorization_ref', ''), 120)}",
        f"- Expires: {_md(engagement.get('expires_at', ''), 40)}",
        f"- Origins: {', '.join(_md(o, 80) for o in engagement.get('origins', []))}",
        f"- Methods: {', '.join(_md(m, 10) for m in engagement.get('methods', []))}",
        f"- Path prefixes: {', '.join(_md(p, 60) for p in engagement.get('path_prefixes', []))}",
        f"- Mutations allowed: {bool(engagement.get('mutation_allowed', False))}",
        "",
        "## What ran",
        "",
        "| Adapter | Status | Captures | Duration | Note |",
        "| --- | --- | --- | --- | --- |",
    ]
    for adapter in adapters:
        lines.append(
            f"| {_md(adapter.get('adapter', ''), 40)} "
            f"| {_md(adapter.get('status', ''), 20)} "
            f"| {_md(adapter.get('requests', 0), 10)} "
            f"| {float(adapter.get('duration_s', 0.0)):.2f}s "
            f"| {_md(adapter.get('note', ''), 120)} |"
        )

    lines += [
        "",
        "## Coverage",
        "",
        f"- Requests made: {coverage.requests_made} of {coverage.request_limit}",
        f"- Targets visited: {len(coverage.targets_visited)} (seeds: {len(coverage.targets_planned)})",
        f"- Stop reason: {_md(coverage.stop_reason or 'completed', 120)}",
    ]
    if coverage.targets_visited:
        lines.append("- Visited:")
        lines += [f"  - `{_md(url, 160)}`" for url in coverage.targets_visited]
    unvisited = [url for url in coverage.targets_planned if url not in coverage.targets_visited]
    if unvisited:
        lines.append("- Planned but not visited:")
        lines += [f"  - `{_md(url, 160)}`" for url in unvisited]
    if coverage.skipped:
        lines.append("- Skipped:")
        lines += [
            f"  - `{_md(item.get('url', ''), 160)}`: {_md(item.get('reason', ''), 120)}"
            for item in coverage.skipped
        ]
    if coverage.truncated_pages:
        lines.append("- Captures truncated (size bound reached):")
        lines += [f"  - `{_md(url, 160)}`" for url in coverage.truncated_pages]
    if coverage.entries:
        lines += [
            "",
            "### Coverage ledger",
            "",
            "| Surface | Risk area | Outcome | Source | Evidence IDs | Evidence |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for entry in coverage.entries:
            evidence_ids = ", ".join(entry.evidence_ids) or "-"
            lines.append(
                f"| {_md(entry.surface, 80)} "
                f"| {_md(entry.risk_area, 80)} "
                f"| {entry.outcome.value} "
                f"| {_md(entry.source, 20)} "
                f"| {_md(evidence_ids, 80)} "
                f"| {_md(entry.evidence, 160)} |"
            )

    lines += [
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines += ["No findings were produced from the captured evidence.", ""]
    else:
        lines += [
            "| ID | Severity | State | Confidence | Title | Endpoint | Evidence |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for finding in findings:
            lines.append(
                f"| {finding.id} | {finding.severity.value} | {finding.state.value} "
                f"| {finding.confidence.value} | {_md(finding.title, 120)} "
                f"| `{_md(finding.endpoint, 80)}` "
                f"| {', '.join(finding.evidence_ids)} |"
            )
        lines.append("")
        for finding in findings:
            lines += [
                f"### {finding.id} — {_md(finding.title, 160)}",
                "",
                f"- Severity: **{finding.severity.value}**",
                f"- State: **{finding.state.value}**",
                f"- Confidence: {finding.confidence.value}",
                f"- Asset: `{_md(finding.asset, 120)}`",
                f"- Endpoint: `{_md(finding.endpoint, 120)}`",
                f"- Check: `{_md(finding.check_id, 80)}` version {_md(finding.check_version, 10)}",
                f"- Evidence: {', '.join(finding.evidence_ids) or 'none'}",
                f"- Reference: {_md(finding.weakness_ref or 'n/a', 40)}",
                "",
                f"{_md_block(finding.detail or finding.summary)}",
                "",
            ]
            if finding.reproduction or finding.reproduction_detail:
                lines += _repro_lines(finding, record_index)
            lines += [
                f"- Observed impact: {_md(finding.impact or 'none demonstrated', 300)}",
                f"- Remediation: {_md(finding.remediation or 'n/a', 300)}",
            ]
            if finding.cwe:
                lines.append(f"- CWE: `{_md(finding.cwe, 40)}`")
            if finding.cvss_score is not None:
                lines.append(f"- CVSS: {finding.cvss_score:.1f} `{_md(finding.cvss_vector, 120)}`")
            if finding.exchange_ids:
                lines.append(
                    "- HTTP exchanges: " + ", ".join(_md(item, 40) for item in finding.exchange_ids)
                )
            if finding.assumptions:
                lines.append("- Assumptions:")
                lines += [f"  - {_md(item, 300)}" for item in finding.assumptions]
            if finding.counterevidence:
                lines.append("- Counterevidence:")
                lines += [f"  - {_md(item, 300)}" for item in finding.counterevidence]
            if finding.confidence_rationale:
                lines.append(f"- Confidence rationale: {_md(finding.confidence_rationale, 300)}")
            if finding.severity_change_conditions:
                lines.append("- Severity changes if:")
                lines += [f"  - {_md(item, 300)}" for item in finding.severity_change_conditions]
            for location in finding.code_locations:
                lines.append(
                    "- Code: "
                    f"`{_md(location.get('file', ''), 160)}:"
                    f"{_md(location.get('start_line', '?'), 10)}-"
                    f"{_md(location.get('end_line', '?'), 10)}`"
                )
            if finding.limitations:
                lines.append("- Limitations:")
                lines += [f"  - {_md(item, 200)}" for item in finding.limitations]
            if finding.regression_recipe:
                lines.append("- Regression recipe:")
                lines += [f"  - {_md(step, 200)}" for step in finding.regression_recipe]
            lines.append("")

    lines += [
        "## Evidence index",
        "",
        "| ID | Kind | Status | URL | Body SHA-256 | Truncated |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in evidence:
        lines.append(
            f"| {_md(item.get('id', ''), 20)} "
            f"| {_md(item.get('kind', ''), 20)} "
            f"| {_md(item.get('status') if item.get('status') is not None else '-', 10)} "
            f"| `{_md(item.get('url', ''), 160)}` "
            f"| `{_md(item.get('body_sha256', ''), 64)}` "
            f"| {bool(item.get('truncated'))} |"
        )

    lines += [
        "",
        "## Untested areas and limits",
        "",
        (
            f"- Validation profile: `{_md(engagement.get('profile', ''), 40)}`; "
            "inert HTML and redirect markers were sent; no browser or script execution."
            if validation_run
            else f"- Observation profile: `{_md(engagement.get('profile', ''), 40)}`; no payloads were sent."
        ),
        (
            "- Only explicit GET probes were sent; redirects were not followed and no crawl ran."
            if validation_run
            else "- Only GET requests and rendered pages were observed."
        ),
        "- Authentication, two-account authorization, uploads, and business logic were not tested.",
    ]
    for adapter in adapters:
        if adapter.get("status") != "completed":
            lines.append(
                f"- `{_md(adapter.get('adapter', ''), 40)}` did not complete: "
                f"{_md(adapter.get('note', ''), 200)}"
            )
    blocked = coverage.skipped
    if blocked:
        lines.append(f"- {len(blocked)} destination(s) were blocked by scope enforcement.")
    lines += [
        "- A missing header or a version string is an observation, not a validated weakness.",
        "- Absence of findings is not evidence of safety.",
        "",
    ]
    if evidence_integrity:
        lines += [
            "## Evidence integrity",
            "",
            "Evidence verification failed; reproduction links and coverage claims were withheld.",
            *[f"- {_md(problem, 200)}" for problem in evidence_integrity],
            "",
        ]
    lines += [
        "## Budget",
        "",
        f"- Delegate calls: {budget.get('calls', 0)} of {budget.get('limits', {}).get('max_delegate_calls_per_run', 0)}",
        f"- Spend: ${float(budget.get('spent_usd', 0.0)):.4f}",
        f"- Elapsed: {float(budget.get('elapsed_seconds', 0.0)):.1f}s",
        "",
        "Report generated by vsw. Target content is untrusted data and was escaped before rendering.",
        "",
    ]
    return "\n".join(lines)


def write_report(
    run_dir: Path,
    *,
    payload: dict[str, Any],
    markdown: str,
) -> tuple[Path, Path]:
    """Write report files inside the run directory only."""
    run_dir = run_dir.resolve()
    md_path = _safe(run_dir, "report.md")
    safe_payload = redact_value(redact_export_payload(payload))
    md_path.write_text(markdown, encoding="utf-8")
    json_path = _write_json(run_dir, "findings.json", safe_payload)
    return md_path, json_path


def write_observation_artifacts(
    run_dir: Path,
    *,
    run_id: str,
    status: str,
    target: str,
    engagement: Engagement,
    findings: list[Finding],
    coverage: Coverage,
    evidence: list[dict[str, Any]],
    adapters: list[dict[str, Any]],
    budget: dict[str, Any],
    evidence_integrity: list[str],
    started: str,
    finished: str,
) -> dict[str, Any]:
    """Build and write every observation artifact from one redacted snapshot."""
    run_dir = run_dir.resolve()
    engagement_summary: dict[str, Any] = redact_value(
        {
            "id": engagement.id,
            "owner": engagement.owner,
            "approver": engagement.approver,
            "authorization_ref": engagement.authorization_ref,
            "profile": engagement.profile.value,
            "expires_at": engagement.expires_at,
            "origins": engagement.origins,
            "methods": engagement.methods,
            "path_prefixes": engagement.path_prefixes,
            "mutation_allowed": engagement.mutation_allowed,
            "manifest_sha256": manifest_hash(engagement),
        }
    )
    safe_evidence: list[dict[str, Any]] = redact_value(evidence) if not evidence_integrity else []
    record_index = {str(item["id"]): item for item in safe_evidence if item.get("id")}
    safe_findings = [finding.model_copy(deep=True) for finding in findings]
    if evidence_integrity:
        for finding in safe_findings:
            finding.state = FindingState.INCONCLUSIVE
            finding.limitations.append(
                "Evidence integrity failed; the finding cannot be confirmed."
            )
    exported_findings = [finding_export(finding, record_index) for finding in safe_findings]
    safe_coverage = Coverage.model_validate(redact_value(coverage.model_dump(mode="json")))
    if evidence_integrity:
        safe_coverage.entries = [
            entry.model_copy(
                update={
                    "outcome": CoverageOutcome.NEEDS_FOLLOW_UP,
                    "evidence": "evidence integrity failed; re-run required",
                    "evidence_ids": [],
                }
            )
            for entry in safe_coverage.entries
        ]
    safe_adapters: list[dict[str, Any]] = redact_value(adapters)
    safe_budget: dict[str, Any] = redact_value(budget)
    payload: dict[str, Any] = {
        "run_id": run_id,
        "status": status,
        "stage": "M2" if any(item.get("adapter") == "validation" for item in adapters) else "M1",
        "mode": "live-local",
        "started": started,
        "finished": finished,
        "engagement": engagement_summary,
        "coverage": safe_coverage.model_dump(mode="json"),
        "findings": exported_findings,
        "evidence": safe_evidence,
        "adapters": safe_adapters,
        "budget": safe_budget,
        "evidence_integrity": redact_value(evidence_integrity),
        "target": redact_text(target),
    }
    # The returned payload is the exact redacted snapshot written to disk.
    payload = redact_value(redact_export_payload(payload))
    markdown = render_markdown(
        run_id=run_id,
        engagement=engagement_summary,
        findings=[Finding.model_validate(item) for item in exported_findings],
        coverage=safe_coverage,
        evidence=safe_evidence,
        adapters=safe_adapters,
        budget=safe_budget,
        started=started,
        finished=finished,
        status=status,
        evidence_integrity=payload["evidence_integrity"],
    )
    write_report(run_dir, payload=payload, markdown=markdown)
    _write_json(run_dir, "coverage.json", payload["coverage"])
    _write_json(
        run_dir,
        "exchanges.json",
        {
            "run_id": run_id,
            "exchanges": [
                {
                    "exchange_id": item["id"],
                    "evidence_id": item["id"],
                    "method": item.get("method"),
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "captured_at": item.get("captured_at"),
                    "record_sha256": item.get("record_sha256"),
                    "body_sha256": item.get("body_sha256"),
                }
                for item in safe_evidence
                if item.get("kind") == "http" and item.get("id")
            ],
        },
    )
    _write_json(
        run_dir,
        "run.json",
        {
            "run_id": run_id,
            "stage": payload["stage"],
            "target": payload["target"],
            "engagement": engagement_summary["id"],
            "findings": len(exported_findings),
            "validated": sum(
                item["state"] == FindingState.VALIDATED.value for item in exported_findings
            ),
            "evidence_integrity": payload["evidence_integrity"],
            "status": status,
        },
    )
    return payload


def _write_json(root: Path, name: str, payload: Any) -> Path:
    path = _safe(root, name)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _safe(root: Path, name: str) -> Path:
    target = (root / name).resolve()
    if not str(target).startswith(str(root) + "/") and target != root:
        raise ValueError(f"refusing to write outside the run directory: {name}")
    return target
