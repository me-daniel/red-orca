"""Passive HTTP observation: bounded, one request at a time, no payloads."""

from __future__ import annotations

import time
from urllib.parse import urljoin, urlsplit

import httpx

from ..analysis import analyze_http
from ..domain import CheckPlan, Engagement, Finding
from ..evidence import MAX_BODY_BYTES, EvidenceRecord, EvidenceStore, redact_set_cookie
from ..scope import ScopeDenied, ScopeGuard
from .base import BaseAdapter

USER_AGENT = "vsw/0.1 (local lab observation)"
MAX_REDIRECTS = 5
ACTION_HINTS = ("logout", "signout", "delete", "remove", "reset", "action=", "confirm")


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
            methods=list(self.engagement.methods),
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
            try:
                self.guard.check(current, "GET")
            except ScopeDenied as exc:
                self.guard.record_blocked("redirect" if records else "request", current, exc.reason)
                return records
            origin = self._origin(current)
            self.guard.wait_for_rate(origin)
            try:
                body, size_capped, response = self._stream(current)
            except httpx.HTTPError as exc:
                self.guard.stop_reason = f"target unhealthy: {type(exc).__name__}"
                self.guard.record_blocked(
                    "target", current, f"request failed: {type(exc).__name__}"
                )
                self.failures.append(f"GET {current}: {type(exc).__name__}")
                return records

            record = self.store.capture(
                kind="http",
                url=current,
                method="GET",
                status=response.status_code,
                request_headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"},
                response_headers=dict(response.headers.items()),
                body=body,
                truncated=size_capped,
                source=self.name,
                notes={
                    "content_type": response.headers.get("content-type", ""),
                    "set_cookie": [
                        redact_set_cookie(value)
                        for value in response.headers.get_list("set-cookie")
                    ],
                    "final_url": str(response.url),
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

    def _stream(self, url: str) -> tuple[bytes, bool, httpx.Response]:
        """Download at most one body bound; never buffer an unbounded response."""
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*"}
        with httpx.stream(
            "GET",
            url,
            headers=headers,
            timeout=self.timeout_s,
            follow_redirects=False,
        ) as response:
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
