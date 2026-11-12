"""Deterministic analysis.

Every finding starts from a captured record. A missing header or a version
string is `observed`, never `validated`: validation needs a captured,
reproducible observable effect.
"""

from __future__ import annotations

import html
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..domain import Confidence, Finding, FindingState, Reproduction, ReproStep, Severity
from ..evidence import EvidenceRecord

CHECK_VERSION = "1"

SECURITY_HEADERS: list[tuple[str, str, Severity]] = [
    ("content-security-policy", "content-security-policy", Severity.MEDIUM),
    ("x-content-type-options", "x-content-type-options", Severity.LOW),
    ("x-frame-options", "frame-options", Severity.LOW),
    ("referrer-policy", "referrer-policy", Severity.LOW),
    ("permissions-policy", "permissions-policy", Severity.INFO),
]

_SUBRESOURCE = re.compile(
    r"""<(?:script|img|iframe|link|audio|video|source)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)


def _finding(
    *,
    record: EvidenceRecord,
    check_id: str,
    title: str,
    severity: Severity,
    state: FindingState = FindingState.OBSERVED,
    confidence: Confidence = Confidence.HIGH,
    weakness_ref: str = "",
    summary: str = "",
    detail: str = "",
    reproduction: list[str] | None = None,
    impact: str = "",
    limitations: list[str] | None = None,
    remediation: str = "",
    regression: list[str] | None = None,
    now: float | None = None,
) -> Finding:
    parts = urlsplit(record.url)
    entry_target = parts.path or "/"
    if parts.query:
        entry_target += "?" + parts.query
    reproduction_detail = None
    if record.request_text and record.response_text:
        reproduction_detail = Reproduction(
            entry_point=f"{record.method} {entry_target}",
            steps=[
                ReproStep(
                    request=record.request_text,
                    response=record.response_text,
                    expected=summary or title,
                    proves=summary or title,
                    exchange_id=record.id,
                    evidence_ids=[record.id],
                )
            ],
            provenance=f"{check_id} v{CHECK_VERSION} from {record.source or 'capture'}",
        )
    return Finding(
        id="",
        title=title,
        asset=f"{parts.scheme}://{parts.netloc}",
        endpoint=parts.path or "/",
        check_id=check_id,
        check_version=CHECK_VERSION,
        severity=severity,
        confidence=confidence,
        state=state,
        weakness_ref=weakness_ref,
        evidence_ids=[record.id],
        summary=summary or title,
        detail=detail,
        reproduction=reproduction or [],
        reproduction_detail=reproduction_detail,
        impact=impact,
        limitations=limitations or [],
        remediation=remediation,
        regression_recipe=regression or [],
    )


def analyze_http(
    record: EvidenceRecord, profile: str = "lab", now: float | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    if record.status is None or not 200 <= record.status < 300:
        return findings
    headers = record.response_headers
    lowered = {name.lower(): value for name, value in headers.items()}
    content_type = str(record.notes.get("content_type") or "").lower()
    scheme = urlsplit(record.url).scheme

    present = set(lowered)
    csp = str(lowered.get("content-security-policy", "")).lower()
    for header, check_id, severity in SECURITY_HEADERS:
        if header in present:
            continue
        if header == "x-frame-options" and "frame-ancestors" in csp:
            continue
        findings.append(
            _finding(
                record=record,
                check_id=f"headers.{check_id}",
                title=f"Missing {header} response header",
                severity=severity,
                weakness_ref="CWE-693",
                summary=f"The response does not set {header}.",
                detail=(
                    f"GET {record.url} returned status {record.status} without a "
                    f"{header} header. Header absence alone does not demonstrate impact."
                ),
                reproduction=[f"GET {record.url}", f"Inspect response headers for {header}"],
                impact="Unproven from header absence alone.",
                limitations=[
                    "Header absence is an observation, not a validated weakness.",
                    "Impact depends on browser behavior and application context.",
                ],
                remediation=f"Set an appropriate {header} header on this response.",
                regression=[f"GET {record.url} and assert the response includes {header}."],
            )
        )

    if scheme == "https" and "strict-transport-security" not in present:
        findings.append(
            _finding(
                record=record,
                check_id="headers.hsts",
                title="Missing Strict-Transport-Security header",
                severity=Severity.LOW,
                weakness_ref="CWE-319",
                summary="The HTTPS response does not set HSTS.",
                reproduction=[f"GET {record.url}", "Inspect response headers for HSTS"],
                remediation="Send Strict-Transport-Security with a bounded max-age.",
                regression=[f"GET {record.url} and assert HSTS is present."],
            )
        )

    for raw_cookie in record.notes.get("set_cookie") or []:
        flags = _cookie_flags(str(raw_cookie))
        name = str(raw_cookie).split("=", 1)[0]
        missing = []
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if scheme == "https" and "secure" not in flags:
            missing.append("Secure")
        if "samesite" not in flags:
            missing.append("SameSite")
        if not missing:
            continue
        findings.append(
            _finding(
                record=record,
                check_id=f"cookies.flags.{name}",
                title=f"Cookie {name} is missing {', '.join(missing)}",
                severity=Severity.MEDIUM if "HttpOnly" in missing else Severity.LOW,
                weakness_ref="CWE-1004",
                summary=f"Set-Cookie for {name} lacks {', '.join(missing)}.",
                detail=(
                    f"Observed Set-Cookie attributes: {sorted(flags)}. "
                    f"Missing: {', '.join(missing)}."
                ),
                reproduction=[f"GET {record.url}", f"Inspect Set-Cookie for {name}"],
                impact="Not demonstrated; depends on how the cookie is used.",
                limitations=["Cookie value was redacted before storage."],
                remediation=f"Add {', '.join(missing)} to the {name} cookie.",
                regression=[f"GET {record.url} and assert {name} sets {', '.join(missing)}."],
            )
        )

    server = str(lowered.get("server", ""))
    if re.search(r"\d", server):
        findings.append(
            _finding(
                record=record,
                check_id="headers.server_version",
                title="Server header discloses software version",
                severity=Severity.INFO,
                weakness_ref="CWE-200",
                summary=f"Server header: {server}",
                reproduction=[f"GET {record.url}", "Inspect the Server header"],
                remediation="Send a generic Server header.",
                regression=[f"GET {record.url} and assert Server has no version."],
            )
        )

    if "html" in content_type:
        findings.extend(_reflection(record))
        findings.extend(_subresources(record, scheme))
    return findings


def _cookie_flags(raw: str) -> set[str]:
    parts = [part.strip().lower() for part in raw.split(";")][1:]
    flags = set()
    for part in parts:
        flags.add(part.split("=", 1)[0].strip())
    return flags


def _reflection(record: EvidenceRecord) -> list[Finding]:
    findings: list[Finding] = []
    query = parse_qs(urlsplit(record.url).query, keep_blank_values=False)
    for name, values in query.items():
        for value in values:
            if not 3 <= len(value) <= 64:
                continue
            if value not in record.body:
                continue
            escaped = html.escape(value, quote=True)
            if escaped != value and escaped in record.body and value not in record.body:
                continue
            # A plain alphanumeric marker reads the same whether or not the
            # server encoded it, so only markup-bearing values prove the gap.
            proves_encoding = any(char in value for char in "<>\"'")
            state = FindingState.VALIDATED if proves_encoding else FindingState.OBSERVED
            if proves_encoding:
                summary = (
                    f"The value of {name} contains markup characters and appears "
                    "verbatim in the HTML response, so it was not encoded."
                )
                impact = (
                    "Markup is not encoded. Script execution was not attempted and is "
                    "not claimed; impact beyond reflection is unproven."
                )
                limitations = [
                    "No script was executed; this is a reflection observation.",
                    "Only the captured parameter values were tested.",
                ]
            else:
                summary = (
                    f"The value of {name} appears verbatim in the HTML response. The "
                    "value has no markup characters, so encoding cannot be inferred "
                    "from this capture alone."
                )
                impact = "Not demonstrated; the response may still encode this value."
                limitations = [
                    (
                        "The reflected value contains no characters that would "
                        "distinguish encoded from unencoded output."
                    ),
                    "Re-run with a markup-bearing value to test encoding.",
                ]
            finding = _finding(
                record=record,
                check_id=f"reflection.{name}",
                title=(
                    f"Query parameter {name} is reflected unescaped"
                    if proves_encoding
                    else f"Query parameter {name} is reflected"
                ),
                severity=Severity.MEDIUM if proves_encoding else Severity.INFO,
                state=state,
                weakness_ref="CWE-79",
                summary=summary,
                detail=(
                    f"Sent {name}={value!r}; the response body contains the identical "
                    "string in an HTML context. The observation is reproducible from "
                    "the captured record."
                ),
                reproduction=[
                    f"GET {record.url}",
                    "Search the response body for the parameter value",
                ],
                impact=impact,
                limitations=limitations,
                remediation="Encode contextually on output; do not build HTML from raw input.",
                regression=[f"GET {record.url} with a marker value and assert it is HTML-encoded."],
            )
            findings.append(finding)
    return findings


def _subresources(record: EvidenceRecord, scheme: str) -> list[Finding]:
    findings: list[Finding] = []
    origin = _origin(record.url)
    seen: set[str] = set()
    for match in _SUBRESOURCE.finditer(record.body):
        target = match.group(1).strip()
        parts = urlsplit(target)
        if not parts.scheme or not parts.netloc:
            continue
        if _origin(target) == origin:
            continue
        if target in seen:
            continue
        seen.add(target)
        findings.append(
            _finding(
                record=record,
                check_id="browser.external_subresource",
                title=f"Page loads an asset from {parts.netloc}",
                severity=Severity.INFO,
                weakness_ref="CWE-829",
                summary=f"{record.url} references {target}, outside the approved origin.",
                detail="The reference is visible in the captured HTML.",
                reproduction=[f"GET {record.url}", f"Search the body for {target}"],
                impact="Not demonstrated; recorded as a data flow.",
                limitations=["No asset was fetched from the external origin."],
                remediation="Serve assets from the approved origin or document the dependency.",
            )
        )
    if scheme == "https":
        for match in _SUBRESOURCE.finditer(record.body):
            target = match.group(1).strip()
            if target.startswith("http://"):
                findings.append(
                    _finding(
                        record=record,
                        check_id="browser.mixed_content",
                        title="HTTPS page references an HTTP subresource",
                        severity=Severity.LOW,
                        weakness_ref="CWE-311",
                        summary=f"Mixed content reference: {target}",
                        reproduction=[f"GET {record.url}", f"Search the body for {target}"],
                        limitations=["Subresource was not fetched."],
                        remediation="Reference the asset over HTTPS.",
                    )
                )
                break
    return findings


def analyze_browser(
    record: EvidenceRecord, profile: str = "lab", now: float | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    requests = record.notes.get("requests") or []
    origin = _origin(record.url)
    for request in requests:
        if not isinstance(request, dict):
            continue
        blocked = bool(request.get("blocked"))
        url = str(request.get("url") or "")
        request_origin = str(request.get("origin") or _origin(url))
        if request_origin == origin:
            continue
        reason = str(request.get("reason") or "")
        findings.append(
            _finding(
                record=record,
                check_id="browser.third_party_request",
                title=f"Browser requested {request_origin}",
                severity=Severity.INFO,
                weakness_ref="CWE-829",
                summary=(
                    f"The page attempted a request to {url}"
                    + (" and it was blocked by scope enforcement." if blocked else ".")
                ),
                detail=f"reason: {reason}" if reason else "",
                reproduction=["Load the page in a browser with network capture enabled"],
                impact="Not demonstrated; recorded as a data flow.",
                limitations=["Out-of-scope destinations are blocked and never contacted."],
                remediation="Remove the dependency or serve it from the approved origin.",
            )
        )

    # Data-flow findings above stand on their own. Cookie and form checks only
    # mean something for a page the browser actually rendered successfully.
    if record.status is not None and not 200 <= record.status < 300:
        return findings

    for cookie in record.notes.get("cookies") or []:
        if not isinstance(cookie, dict):
            continue
        missing = []
        if not cookie.get("httpOnly"):
            missing.append("HttpOnly")
        if not cookie.get("secure"):
            missing.append("Secure")
        if str(cookie.get("sameSite") or "None").lower() in {"none", ""}:
            missing.append("SameSite")
        if not missing:
            continue
        name = str(cookie.get("name"))
        findings.append(
            _finding(
                record=record,
                check_id=f"cookies.flags.{name}",
                title=f"Cookie {name} is missing {', '.join(missing)}",
                severity=Severity.MEDIUM if "HttpOnly" in missing else Severity.LOW,
                weakness_ref="CWE-1004",
                summary=f"Browser context holds {name} without {', '.join(missing)}.",
                reproduction=["Load the page and inspect document.cookie attributes"],
                limitations=["Cookie value was redacted."],
                remediation=f"Add {', '.join(missing)} to {name}.",
            )
        )

    for form in record.notes.get("forms") or []:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "get").lower()
        action = str(form.get("action") or "")
        if method == "get" and any(
            hint in action.lower() for hint in ("delete", "logout", "reset", "action")
        ):
            findings.append(
                _finding(
                    record=record,
                    check_id="forms.state_changing_get",
                    title="Form uses GET for a state-changing action",
                    severity=Severity.LOW,
                    summary=f"Form action {action or '(self)'} uses GET.",
                    reproduction=["Load the page", "Inspect the form method and action"],
                    limitations=["The form was not submitted."],
                    remediation="Use POST with a CSRF token for state changes.",
                )
            )
    return findings


def _origin(url: str) -> str:
    parts = urlsplit(url)
    default = 443 if parts.scheme == "https" else 80
    host = parts.hostname or ""
    port = parts.port or default
    return f"{parts.scheme}://{host}" if port == default else f"{parts.scheme}://{host}:{port}"


def analyze_records(records: list[dict[str, Any]]) -> list[Finding]:
    """Convenience wrapper used by tests and reports."""
    findings: list[Finding] = []
    for raw in records:
        record = EvidenceRecord(**{k: v for k, v in raw.items() if k != "record_sha256"})
        if record.kind == "http":
            findings.extend(analyze_http(record))
        elif record.kind == "browser":
            findings.extend(analyze_browser(record))
    return findings
