"""Passive HTTP observation: bounded, one request at a time, no payloads."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from urllib.parse import urljoin, urlsplit

import httpx

from ..analysis import analyze_http
from ..domain import CheckPlan, Engagement, Finding
from ..evidence import MAX_BODY_BYTES, EvidenceRecord, EvidenceStore, redact_set_cookie
from ..scope import PinnedTarget, ScopeDenied, ScopeGuard
from .base import BaseAdapter

USER_AGENT = "vsw/0.1 (local lab observation)"
MAX_REDIRECTS = 5
ACTION_HINTS = ("logout", "signout", "delete", "remove", "reset", "action=", "confirm")


class _ProgressStream(httpx.SyncByteStream):
    """Check policy around every raw read, including decoder-buffered chunks."""

    def __init__(self, stream: httpx.SyncByteStream, check: Callable[[], None]) -> None:
        self.stream = stream
        self.check = check

    def __iter__(self) -> Iterator[bytes]:
        chunks = iter(self.stream)
        while True:
            self.check()
            try:
                chunk = next(chunks)
            except StopIteration:
                return
            self.check()
            yield chunk

    def close(self) -> None:
        self.stream.close()


class PassiveHttpAdapter(BaseAdapter):
    name = "passive-http"

    def __init__(
        self,
        guard: ScopeGuard,
        store: EvidenceStore,
        engagement: Engagement,
        timeout_s: float = 10.0,
    ) -> None:
        super().__init__()
        self.guard = guard
        self.store = store
        self.engagement = engagement
        self.timeout_s = timeout_s
        self.visited: list[str] = []
        self.failures: list[str] = []
        self._progress_check: Callable[[], None] | None = None
        self._allow_compression = True

    def capabilities(self) -> set[str]:
        return {
            "http.headers",
            "http.cookies",
            "http.reflection",
            "http.subresources",
            "http.redirects",
        }

    def validate_config(self) -> None:
        if not self.engagement.origins:
            raise ValueError("no approved origins")

    def plan(self, seeds: list[str]) -> CheckPlan:
        return CheckPlan(
            adapter=self.name,
            destinations=list(seeds),
            methods=["GET"],
            mutations=False,
            estimated_requests=min(len(seeds), self.engagement.max_requests),
            cleanup="none",
        )

    def execute(self, plan: CheckPlan) -> list[EvidenceRecord]:
        records: list[EvidenceRecord] = []
        queue = list(plan.destinations)
        seen: set[str] = set()
        while queue and not self.cancelled:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if self.guard.remaining_requests() <= 0:
                self.guard.stop_reason = "request limit reached"
                break
            chain = self._fetch(url)
            if not chain:
                continue
            records.extend(chain)
            self.visited.append(url)
            for link in self._links(chain[-1]):
                if link not in seen:
                    queue.append(link)
        return records

    # -- internals -------------------------------------------------------
    def _fetch(self, url: str) -> list[EvidenceRecord]:
        records: list[EvidenceRecord] = []
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            if urlsplit(current).scheme != "http":
                reason = "https observation is not enabled"
                self.guard.record_blocked("request", current, reason)
                self.failures.append(f"GET {current}: {reason}")
                return records
            try:
                target = self.guard.authorize(current, "GET")
            except ScopeDenied as exc:
                self.guard.record_blocked("redirect" if records else "request", current, exc.reason)
                return records
            self.guard.wait_for_rate(target.origin)
            try:
                body, size_capped, response = self._stream(current, target)
            except httpx.HTTPError as exc:
                self.guard.stop_reason = f"target unhealthy: {type(exc).__name__}"
                self.guard.record_blocked(
                    "target", current, f"request failed: {type(exc).__name__}"
                )
                self.failures.append(f"GET {current}: {type(exc).__name__}")
                return records

            parts = urlsplit(current)
            request_headers = {
                "User-Agent": USER_AGENT,
                "Accept": "text/html,*/*",
                "Host": target.host_header,
            }
            target_path = parts.path or "/"
            if parts.query:
                target_path += "?" + parts.query
            request_text = (
                f"GET {target_path} HTTP/1.1\n"
                + "\n".join(f"{name}: {value}" for name, value in request_headers.items())
                + "\n\n"
            )
            reason = response.reason_phrase or ""
            response_text = (
                f"HTTP/1.1 {response.status_code} {reason}\n"
                + "\n".join(f"{name}: {value}" for name, value in response.headers.items())
                + "\n\n"
                + body.decode("utf-8", errors="replace")
            )
            record = self.store.capture(
                kind="http",
                url=current,
                method="GET",
                status=response.status_code,
                request_headers=request_headers,
                response_headers=dict(response.headers.items()),
                body=body,
                request_text=request_text,
                response_text=response_text,
                truncated=size_capped,
                source=self.name,
                notes={
                    "content_type": response.headers.get("content-type", ""),
                    "set_cookie": [
                        redact_set_cookie(value)
                        for value in response.headers.get_list("set-cookie")
                    ],
                    "final_url": current,
                    "peer": target.address,
                    "redirected": current != url,
                    "hop": len(records),
                    "download_capped": size_capped,
                },
            )
            records.append(record)
            location = response.headers.get("location")
            if response.is_redirect and location:
                current = urljoin(current, location)
                continue
            return records
        return records

    def _stream(self, url: str, target: PinnedTarget) -> tuple[bytes, bool, httpx.Response]:
        """Download at most one body bound; never buffer an unbounded response.

        The URL sent over the wire carries the address the guard checked, with
        the approved hostname in `Host`. Re-resolving here would reopen the
        rebinding gap the scope check exists to close.
        """
        parts = urlsplit(url)
        netloc = target.url_host if target.port == 80 else f"{target.url_host}:{target.port}"
        pinned = f"{target.scheme}://{netloc}{parts.path or '/'}"
        if parts.query:
            pinned = f"{pinned}?{parts.query}"
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,*/*",
            "Host": target.host_header,
        }
        if not self._allow_compression:
            headers["Accept-Encoding"] = "identity"
        with httpx.stream(
            "GET",
            pinned,
            headers=headers,
            timeout=self.timeout_s,
            follow_redirects=False,
            trust_env=False,
        ) as response:
            if self._progress_check is not None:
                self._progress_check()
                assert isinstance(response.stream, httpx.SyncByteStream)
                response.stream = _ProgressStream(response.stream, self._progress_check)
            if not self._allow_compression and response.headers.get(
                "content-encoding", ""
            ).strip().lower() not in {
                "",
                "identity",
            }:
                raise ScopeDenied("validation requires an uncompressed response")
            chunks: list[bytes] = []
            total = 0
            capped = False
            for chunk in response.iter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BODY_BYTES:
                    capped = True
                    chunks = [b"".join(chunks)[:MAX_BODY_BYTES]]
                    break
            return b"".join(chunks), capped, response

    def _links(self, record: EvidenceRecord) -> list[str]:
        """Same-origin GET links only, no action URLs, bounded."""
        content_type = str(record.notes.get("content_type") or "").lower()
        if "html" not in content_type:
            return []
        from html.parser import HTMLParser

        base = record.url
        follow: list[str] = []

        class Parser(HTMLParser):
            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
                if tag != "a":
                    return
                target = dict(attrs).get("href")
                if not target or target.startswith(("#", "mailto:", "javascript:")):
                    return
                absolute = urljoin(base, target)
                parts = urlsplit(absolute)
                if parts.query or parts.fragment:
                    return
                lowered = absolute.lower()
                if any(hint in lowered for hint in ACTION_HINTS):
                    return
                follow.append(absolute)

        Parser().feed(record.body)
        return follow

    def _origin(self, url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.hostname}:{parts.port or 80}"

    def normalize(self, records: list[EvidenceRecord]) -> list[Finding]:
        findings: list[Finding] = []
        for record in records:
            if record.kind != "http":
                continue
            findings.extend(
                analyze_http(record, profile=self.engagement.profile.value, now=time.time())
            )
        return findings
