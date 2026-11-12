"""Report rendering.

Everything that came from a target is escaped before it reaches Markdown or
JSON. Reports always separate observed facts from unproven inference and
always state what was not tested.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .domain import Coverage, Finding, FindingState

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


def _repro_lines(finding: Finding) -> list[str]:
    """Prefer captured reproduction over later prose or a rewritten PoC."""
    detail = finding.reproduction_detail
    if detail is not None and (
        detail.entry_point or detail.prerequisites or detail.steps or detail.provenance
    ):
        lines = ["Reproduction (captured):"]
        if detail.provenance:
            lines.append(f"- Origin: {_md(detail.provenance, 300)}")
        if detail.entry_point:
            lines.append(f"- Entry point: {_md(detail.entry_point, 300)}")
        if detail.prerequisites:
            lines.append("- Prerequisites:")
            lines += [f"  - {_md(item, 300)}" for item in detail.prerequisites]
        for index, step in enumerate(detail.steps, start=1):
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
) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.state.value] = counts.get(finding.state.value, 0) + 1
    validated = counts.get(FindingState.VALIDATED.value, 0)

    lines: list[str] = [
        f"# vsw observation report — {_md(run_id, 80)}",
        "",
        f"- Started: {_md(started, 40)}",
        f"- Finished: {_md(finished, 40)}",
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
            "| Surface | Risk area | Outcome | Source | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for entry in coverage.entries:
            lines.append(
                f"| {_md(entry.surface, 80)} "
                f"| {_md(entry.risk_area, 80)} "
                f"| {entry.outcome.value} "
                f"| {_md(entry.source, 20)} "
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
                lines += _repro_lines(finding)
            lines += [
                f"- Observed impact: {_md(finding.impact or 'none demonstrated', 300)}",
                f"- Remediation: {_md(finding.remediation or 'n/a', 300)}",
            ]
            if finding.cwe:
                lines.append(f"- CWE: `{_md(finding.cwe, 40)}`")
            if finding.cvss_score is not None:
                lines.append(
                    f"- CVSS: {finding.cvss_score:.1f} `{_md(finding.cvss_vector, 120)}`"
                )
            if finding.exchange_ids:
                lines.append(
                    "- HTTP exchanges: "
                    + ", ".join(_md(item, 40) for item in finding.exchange_ids)
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
        f"- Observation profile: `{_md(engagement.get('profile', ''), 40)}`; no payloads were sent.",
        "- Only GET requests and rendered pages were observed.",
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
    json_path = _safe(run_dir, "findings.json")
    md_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return md_path, json_path


def _safe(root: Path, name: str) -> Path:
    target = (root / name).resolve()
    if not str(target).startswith(str(root) + "/") and target != root:
        raise ValueError(f"refusing to write outside the run directory: {name}")
    return target
