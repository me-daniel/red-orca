"""Opt-in, inert validation against one explicitly supplied loopback lab URL.

No discovery, redirect following, browser, script execution, or model calls.
The inherited streaming implementation bounds bodies and uses cooperative I/O:
its timeout bounds each blocking operation, not the entire download. Cancellation
and elapsed time are checked before dispatch, around every raw response chunk,
and after the response; they cannot immediately interrupt an in-flight blocking
read. Compressed responses are rejected. Incomplete exchanges never validate.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import httpx

from ..domain import (
    CheckPlan,
    Confidence,
    Engagement,
    Finding,
    FindingState,
    Profile,
    Reproduction,
    ReproStep,
    Severity,
)
from ..evidence import EvidenceRecord, EvidenceStore
from ..reproduction import verify_reproduction
from ..scope import PinnedTarget, ScopeDenied, ScopeError, ScopeGuard, validate_engagement
from .passive_http import PassiveHttpAdapter

CHECKS = frozenset({"html-injection", "open-redirect"})
REDIRECT_MARKER = "https://example.invalid/vsw-redirect-check"


def _html_text(body: bytes, headers: httpx.Headers) -> tuple[str | None, str]:
    """Accept a narrow encoding profile from transport bytes, before evidence decoding.

    This is deliberately not browser encoding sniffing. Lexically reject all
    encoding-related HTML declarations, even in comments or inert text, rather
    than implement a second, potentially inconsistent HTML/meta parser.
    """
    types = headers.get_list("content-type")
    if len(types) > 1:
        return None, "duplicate Content-Type headers"
    label = ""
    if types:
        parts = types[0].split(";")
        labels = []
        for parameter in parts[1:]:
            match = re.fullmatch(r'\s*([\w-]+)\s*=\s*(?:"([^"\\]*)"|([^\s";,=]+))\s*', parameter)
            if not match:
                return None, "ambiguous Content-Type parameters"
            if match[1].lower() == "charset":
                labels.append(
                    (match[2] if match[2] is not None else match[3]).strip(" \t\r\n\f").lower()
                )
        if len(labels) > 1:
            return None, "duplicate charset parameters"
        if labels and not labels[0]:
            return None, "empty charset label"
        label = labels[0] if labels else ""
    if label not in {"", "utf-8", "utf8", "ascii", "us-ascii"}:
        return None, "unsupported charset label"
    if body.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")):
        return None, "UTF-16/UTF-32 BOM"
    bom = body.startswith(b"\xef\xbb\xbf")
    if bom and label in {"ascii", "us-ascii"}:
        return None, "UTF-8 BOM conflicts with ASCII charset"
    if any(byte in body for byte in (b"\x00", b"\x1b", b"\x0e", b"\x0f", b"~{", b"+/v")):
        return None, "NUL or stateful-encoding ambiguity"
    if re.search(rb"charset|http-equiv", body, re.IGNORECASE):
        return None, "HTML encoding declarations are outside the supported profile"
    encoding = "utf-8" if bom or label in {"utf-8", "utf8"} else "ascii"
    try:
        text = (body[3:] if bom else body).decode(encoding, errors="strict")
    except UnicodeDecodeError:
        return None, f"invalid {encoding} bytes"
    return text, encoding


class _ElementParser(HTMLParser):
    """Ignore inert containers and HTML raw/RCDATA contexts explicitly.

    HTMLParser only treats script/style as raw text by default. Using its raw
    mode for the other contexts prevents fake opening/closing tags in their
    text from escaping a surrounding template or creating a marker element.
    This is not an HTML5 tree builder. Script and frameset documents require
    browser verification, so either start tag invalidates the entire check.
    """

    RAW = frozenset(
        {
            "script",
            "style",
            "textarea",
            "title",
            "xmp",
            "iframe",
            "noembed",
            "noframes",
            "noscript",
            "plaintext",
        }
    )

    def __init__(self, marker: str) -> None:
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.templates = 0
        self.raw: str | None = None
        self.plaintext = False
        self.unsupported = False
        self.found = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.plaintext or self.raw:
            return
        if tag in {"script", "frameset"}:
            self.unsupported = True
            self.found = False
        if tag in self.RAW:
            self.raw = tag
            self.plaintext = tag == "plaintext"
            self.set_cdata_mode(tag)
        elif tag == "template":
            self.templates += 1
        elif not self.unsupported and not self.templates and tag == self.marker and not attrs:
            self.found = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # In HTML, a slash does not close non-void raw text/container elements.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if self.plaintext:
            return
        if self.raw:
            if tag == self.raw:
                self.raw = None
            return
        if tag == "template" and self.templates:
            self.templates -= 1


class ValidationAdapter(PassiveHttpAdapter):
    name = "validation"

    def __init__(
        self,
        guard: ScopeGuard,
        store: EvidenceStore,
        engagement: Engagement,
        checks: list[str],
    ) -> None:
        super().__init__(guard, store, engagement)
        if (
            not checks
            or any(check not in CHECKS for check in checks)
            or len(set(checks)) != len(checks)
        ):
            raise ScopeDenied("checks must be nonempty, unique registered validation checks")
        self.checks = tuple(checks)
        self._plan: CheckPlan | None = None
        self._plan_snapshot = ""
        self._probes: dict[str, tuple[str, str]] = {}
        self._captured: dict[str, dict[str, Any]] = {}
        self._html_bodies: dict[str, str] = {}
        self._executed = False
        self._approved_hash = engagement.approval.approved_manifest_sha256
        self._progress_check = self._ready
        self._allow_compression = False
        self.validate_config()

    def capabilities(self) -> set[str]:
        return set(CHECKS)

    def validate_config(self) -> None:
        try:
            validate_engagement(self.engagement)
            validate_engagement(self.guard.engagement)
        except ScopeError as exc:
            raise ScopeDenied(str(exc)) from exc
        if self.engagement != self.guard.engagement:
            raise ScopeDenied("engagement does not match guard")
        if self.engagement.approval.approved_manifest_sha256 != self._approved_hash:
            raise ScopeDenied("validation approval changed after adapter creation")
        if self.engagement.profile is not Profile.LAB:
            raise ScopeDenied("validation requires the lab profile")
        if self.guard.expired():
            raise ScopeDenied("engagement has expired")
        if self._remaining_time() <= 0:
            raise ScopeDenied("engagement time limit reached")

    def _remaining_time(self) -> float:
        try:
            expiry = datetime.fromisoformat(self.engagement.expires_at)
            seconds = (expiry - datetime.now(UTC)).total_seconds()
        except (ValueError, TypeError):
            raise ScopeDenied("invalid engagement expiry") from None
        return min(seconds, self.engagement.max_wall_seconds - self.guard.elapsed())

    def _ready(self) -> None:
        if self.cancelled:
            raise ScopeDenied("validation cancelled")
        self.validate_config()

    def _pin(self, url: str, *, reserve: bool = False) -> PinnedTarget:
        parts = urlsplit(url)
        if parts.scheme != "http" or not parts.hostname or parts.fragment:
            raise ScopeDenied("validation requires an explicit HTTP URL without a fragment")
        self._request_target(url)
        target = self.guard.authorize(url, "GET", reserve=reserve)
        if target.scheme != "http" or not ipaddress.ip_address(target.address).is_loopback:
            raise ScopeDenied("validation requires a loopback pin")
        return target

    @staticmethod
    def _request_target(url: str) -> bytes:
        """Reject transport normalization before scope reservation or dispatch."""
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        try:
            raw_path = path.encode("ascii")
            if any(ord(char) <= 32 or ord(char) == 127 for char in url):
                raise ValueError("unescaped whitespace/control character")
            if httpx.URL(url).raw_path != raw_path:
                raise ValueError("HTTPX changes the request target")
        except (UnicodeEncodeError, ValueError, httpx.InvalidURL) as exc:
            raise ScopeDenied("validation requires an unchanged ASCII request path/query") from exc
        return raw_path

    def plan(self, seeds: list[str]) -> CheckPlan:
        self._ready()
        if self._plan is not None:
            raise ScopeDenied("validation plan was already generated")
        if len(seeds) != 1:
            raise ScopeDenied("validation requires exactly one explicit target")
        seed = seeds[0]
        self._pin(seed)
        parts = urlsplit(seed)
        probes: dict[str, tuple[str, str]] = {}
        for check in self.checks:
            marker = f"vsw-check-{uuid4()}" if check == "html-injection" else REDIRECT_MARKER
            key = "q" if check == "html-injection" else "to"
            value = f"<{marker}></{marker}>" if check == "html-injection" else marker
            query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
            query.append((key, value))
            url = urlunsplit(parts._replace(query=urlencode(query)))
            self._pin(url)  # Authorize the full final URL, not merely the seed.
            probes[url] = (check, marker)
        self._probes = probes
        self._plan = CheckPlan(
            adapter=self.name,
            destinations=list(probes),
            methods=["GET"],
            mutations=False,
            estimated_requests=len(probes),
            cleanup="none",
        )
        self._plan_snapshot = self._plan.model_dump_json()
        return self._plan

    def _failed(self, url: str, reason: str) -> None:
        self.failures.append(f"GET {url}: {reason}")
        self.guard.stop_reason = reason
        self.guard.record_blocked("validation", url, reason)

    def execute(self, plan: CheckPlan) -> list[EvidenceRecord]:
        if (
            plan is not self._plan
            or plan.model_dump_json() != self._plan_snapshot
            or self._executed
        ):
            raise ScopeDenied("unrecognized, mutated, or already executed validation plan")
        self._executed = True
        records: list[EvidenceRecord] = []
        # Snapshot iteration prevents external mutation during a rate wait.
        for url in tuple(self._probes):
            try:
                self._ready()
                target = self._pin(url)
                self.guard.wait_for_rate(target.origin)
                self._ready()
                target = self._pin(url)  # Recheck scope and the loopback pin after waiting.
                self.timeout_s = min(10.0, self._remaining_time())
                if self.timeout_s <= 0:
                    raise ScopeDenied("engagement time limit reached")
                self._ready()
                target = self._pin(url, reserve=True)
                body, capped, response = self._stream(url, target)
                request = response.request
                if (
                    request.method != "GET"
                    or request.url.raw_path != self._request_target(url)
                    or request.headers.get_list("host") != [target.host_header]
                    or request.url.scheme != target.scheme
                    or request.url.host != target.address
                    or (request.url.port or 80) != target.port
                ):
                    raise ScopeDenied("dispatched request differs from approved pinned target")
            except ScopeDenied as exc:
                self._failed(url, exc.reason)
                break
            except httpx.HTTPError as exc:
                self._failed(url, f"target unhealthy: {type(exc).__name__}")
                break

            unhealthy = response.status_code in {408, 429} or response.status_code >= 500
            complete = not capped and not unhealthy
            if capped:
                self._failed(url, "response download capped")
            elif unhealthy:
                self._failed(url, f"target unhealthy: HTTP {response.status_code}")
            try:
                self._ready()
            except ScopeDenied as exc:
                complete = False
                self._failed(url, exc.reason)
            check, marker = self._probes[url]
            html_text: str | None = None
            encoding = "not applicable"
            if check == "html-injection":
                html_text, encoding = _html_text(body, response.headers)
                if html_text is None:
                    complete = False
                    self._failed(url, f"unsupported HTML encoding: {encoding}")
            # Preserve the approved logical origin, with the exact dispatched
            # target. Raw header tuples retain casing, order and duplicates.
            parts = urlsplit(url)
            actual_path = request.url.raw_path.decode("ascii")
            evidence_url = f"{parts.scheme}://{parts.netloc}{actual_path}"
            headers = dict(request.headers.items())
            # The top-level httpx.stream transport disables HTTP/2 and sends
            # HTTP/1.1 requests independently of the server's response version.
            request_protocol = "HTTP/1.1"
            response_protocol = response.http_version
            request_text = (
                f"{request.method} {actual_path} {request_protocol}\n"
                + "\n".join(
                    f"{k.decode('ascii')}: {v.decode('latin-1')}" for k, v in request.headers.raw
                )
                + "\n\n"
            )
            response_text = (
                f"{response_protocol} {response.status_code} {response.reason_phrase}\n"
                + "\n".join(
                    f"{k.decode('ascii')}: {v.decode('latin-1')}" for k, v in response.headers.raw
                )
                + "\n\n"
                + body.decode("utf-8", errors="replace")
            )
            record = self.store.capture(
                kind="http",
                url=evidence_url,
                method=request.method,
                status=response.status_code,
                request_headers=headers,
                response_headers=dict(response.headers.items()),
                body=body,
                request_text=request_text,
                response_text=response_text,
                truncated=capped,
                source=self.name,
                notes={
                    "check": check,
                    "marker": marker,
                    "complete": complete,
                    "html_encoding": encoding,
                    "html_encoding_supported": html_text is not None,
                    "download_capped": capped,
                    "final_url": evidence_url,
                    "request_http_version": request_protocol,
                    "http_version": response_protocol,
                    "peer": target.address,
                },
            )
            records.append(record)
            self._captured[record.id] = record.as_dict()
            if html_text is not None:
                self._html_bodies[record.id] = html_text
            self.visited.append(url)
            if not complete:
                break
        return records

    def normalize(self, records: list[EvidenceRecord]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        if self.store.verify():
            return findings
        for record in records:
            if record.id in seen or record.url not in self._probes:
                continue
            check, marker = self._probes[record.url]
            if (
                record.kind != "http"
                or record.method != "GET"
                or record.source != self.name
                or record.truncated
                or not record.notes.get("complete")
                or record.notes.get("marker") != marker
                or record.notes.get("check") != check
                or record.notes.get("download_capped")
                or self._captured.get(record.id) != record.as_dict()
                or not self.store.has(record.id)
                or self.store.get(record.id) != record.as_dict()
            ):
                continue
            headers = {k.lower(): v for k, v in record.response_headers.items()}
            if check == "html-injection":
                if (
                    record.status != 200
                    or record.id not in self._html_bodies
                    or not record.notes.get("html_encoding_supported")
                    or headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    != "text/html"
                ):
                    continue
                parser = _ElementParser(marker)
                parser.feed(self._html_bodies[record.id])
                parser.close()
                if parser.unsupported or not parser.found:
                    continue
                title, cwe = "HTML injection", "CWE-79"
                impact = "Attacker-controlled HTML markup is parsed in the response."
                limits = [
                    "No JavaScript execution or session impact tested",
                    (
                        "Conservative parser, not browser-equivalent; script-bearing and frameset "
                        "documents require browser verification and are not validated"
                    ),
                ]
                remediation = "Apply context-appropriate HTML output encoding to untrusted input."
                recipe = [
                    (
                        "Repeat the approved html-injection check against this endpoint with q set "
                        "to a fresh inert <vsw-check-UUID></vsw-check-UUID> element."
                    ),
                    (
                        "Require a complete HTTP 200 text/html capture; the element must no longer "
                        "parse outside inert/raw text contexts after output encoding is fixed."
                    ),
                ]
            else:
                if not (
                    record.status is not None
                    and 300 <= record.status < 400
                    and headers.get("location") == REDIRECT_MARKER
                ):
                    continue
                title, cwe = "Open redirect", "CWE-601"
                impact = "An untrusted destination controls the HTTP redirect Location."
                limits = [
                    "Redirect was not followed; destination content, phishing, and session impact were not tested"
                ]
                remediation = (
                    "Allow only approved local redirect destinations; reject external URLs."
                )
                recipe = [
                    f"Repeat the approved open-redirect check with to={REDIRECT_MARKER}.",
                    (
                        "Inspect the complete captured response without following redirects; "
                        "a 3xx Location must no longer equal the supplied external marker."
                    ),
                ]
            repro = Reproduction(
                entry_point=record.request_text.splitlines()[0],
                steps=[
                    ReproStep(
                        request=record.request_text,
                        response=record.response_text,
                        expected=impact,
                        proves=impact,
                        exchange_id=record.id,
                        evidence_ids=[record.id],
                    )
                ],
                provenance=f"{self.name}: {check} from captured HTTP traffic",
            )
            if not verify_reproduction(repro, {record.id: self.store.get(record.id)}).verified:
                continue
            parts = urlsplit(record.url)
            findings.append(
                Finding(
                    id="",
                    title=title,
                    asset=f"{parts.scheme}://{parts.netloc}",
                    endpoint=parts.path or "/",
                    check_id=check,
                    check_version="1",
                    first_seen=record.captured_at,
                    last_seen=record.captured_at,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    state=FindingState.VALIDATED,
                    cwe=cwe,
                    weakness_ref=cwe,
                    evidence_ids=[record.id],
                    exchange_ids=[record.id],
                    summary=impact,
                    impact=impact,
                    limitations=limits,
                    remediation=remediation,
                    regression_recipe=recipe,
                    reproduction_detail=repro,
                )
            )
            seen.add(record.id)
        return findings
