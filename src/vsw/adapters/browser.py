"""Browser observation with Playwright.

Two layers stop a page from reaching an out-of-scope origin:

- every connection goes through `GuardedProxy`, which sees the hops Playwright's
  interceptor misses (server-side redirects, meta refreshes, script navigation);
- `context.route` aborts off-scope subresources before they are even attempted.

Chromium is the only engine used. Measured against a live off-list origin,
Chromium routes redirect hops through the proxy while WebKit opens them
directly, so WebKit is refused rather than trusted with a documented gap.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit

from ..analysis import analyze_browser
from ..domain import CheckPlan, Engagement, Finding
from ..evidence import EvidenceRecord, EvidenceStore
from ..scope import ScopeDenied, ScopeGuard
from .base import AdapterUnavailable, BaseAdapter
from .proxy import GuardedProxy

MAX_REQUESTS = 100
MAX_BLOCKED = 50
MAX_DOM_CHARS = 512 * 1024

# Chromium exempts loopback from the proxy by default; the lab lives on
# loopback, so the exemption has to be turned off explicitly.
CHROMIUM_PROXY_ARGS = [
    "--proxy-bypass-list=<-loopback>",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--dns-prefetch-disable",
]


class BrowserAdapter(BaseAdapter):
    name = "browser"

    def __init__(
        self,
        guard: ScopeGuard,
        store: EvidenceStore,
        engagement: Engagement,
        timeout_ms: int = 15000,
        browser_name: str = "chromium",
    ) -> None:
        super().__init__()
        self.guard = guard
        self.store = store
        self.engagement = engagement
        self.timeout_ms = timeout_ms
        self.browser_name = browser_name
        self.failures: list[str] = []

    def capabilities(self) -> set[str]:
        return {
            "browser.dom",
            "browser.requests",
            "browser.cookies",
            "browser.storage",
            "browser.console",
        }

    def validate_config(self) -> None:
        if self.browser_name != "chromium":
            raise AdapterUnavailable(
                f"{self.browser_name} opens redirect hops directly; "
                "only chromium keeps every connection behind the scope proxy"
            )
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError as exc:  # pragma: no cover - dependency is pinned
            raise AdapterUnavailable(f"playwright is not installed: {exc}") from exc

    def plan(self, seeds: list[str]) -> CheckPlan:
        return CheckPlan(
            adapter=self.name,
            destinations=list(seeds),
            methods=["GET"],
            mutations=False,
            estimated_requests=len(seeds),
            cleanup="close browser context",
        )

    def execute(self, plan: CheckPlan) -> list[EvidenceRecord]:
        try:
            from playwright.sync_api import Error as PlaywrightError
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover
            raise AdapterUnavailable(f"playwright is not installed: {exc}") from exc

        records: list[EvidenceRecord] = []
        try:
            with sync_playwright() as pw, GuardedProxy(self.guard) as proxy:
                browser_type = getattr(pw, self.browser_name)
                launch: dict[str, Any] = {
                    "proxy": {"server": proxy.url, "bypass": ""},
                    "args": CHROMIUM_PROXY_ARGS,
                }
                browser = browser_type.launch(**launch)
                try:
                    for seed in plan.destinations:
                        if self.cancelled or self.guard.remaining_requests() <= 0:
                            break
                        record = self._visit(browser, seed, PlaywrightError, proxy)
                        if record is not None:
                            records.append(record)
                finally:
                    browser.close()
                self.failures.extend(proxy.errors)
        except PlaywrightError as exc:
            raise AdapterUnavailable(
                f"{self.browser_name} could not start: {str(exc).splitlines()[0]}"
            ) from exc
        return records

    # -- internals -------------------------------------------------------
    def _visit(
        self,
        browser: Any,
        seed: str,
        playwright_error: type[Exception],
        proxy: GuardedProxy,
    ) -> EvidenceRecord | None:
        context = browser.new_context(java_script_enabled=True, service_workers="block")
        page = context.new_page()
        requests: list[dict[str, Any]] = []
        blocked_before = len(proxy.blocked)
        console: list[dict[str, str]] = []

        def guard_request(route: Any) -> None:
            request = route.request
            url = request.url
            if not url.startswith(("http://", "https://")):
                route.continue_()
                return
            try:
                # The proxy reserves the request budget for connections that are
                # actually opened; this is the earlier, cheaper refusal.
                self.guard.check(url, request.method, reserve=False)
            except ScopeDenied as exc:
                if len(requests) < MAX_BLOCKED:
                    self.guard.record_blocked("subresource", url, exc.reason)
                    requests.append(
                        {
                            "method": request.method,
                            "url": url,
                            "blocked": True,
                            "reason": exc.reason,
                        }
                    )
                route.abort()
                return
            if len(requests) < MAX_REQUESTS:
                requests.append(
                    {
                        "method": request.method,
                        "url": url,
                        "resource_type": request.resource_type,
                        "origin": _origin(url),
                        "blocked": False,
                    }
                )
            route.continue_()

        context.route("**/*", guard_request)
        page.on(
            "console",
            lambda message: (
                console.append({"type": message.type, "text": message.text[:2000]})
                if len(console) < MAX_REQUESTS
                else None
            ),
        )

        navigation_error = ""
        final_url = seed
        status: int | None = None
        stopped_by_proxy = False
        try:
            response = page.goto(seed, wait_until="load", timeout=self.timeout_ms)
            final_url = page.url
            status = getattr(response, "status", None) if response is not None else None
            # A redirect hop is checked by the proxy, not by `guard_request`, so
            # a different final URL is recorded as a fact, never blessed.
        except playwright_error as exc:
            navigation_error = str(exc).splitlines()[0]
            # A navigation stopped by the guard, in the interceptor or in the
            # proxy, is the scope working. Only an unexplained failure counts.
            stopped_by_proxy = bool(proxy.blocked[blocked_before:])
            if not stopped_by_proxy:
                self.failures.append(f"navigate {seed}: {navigation_error}")

        html = ""
        dom_capped = False
        if not stopped_by_proxy:
            try:
                html = page.content()
            except playwright_error as exc:
                self.failures.append(f"dom {seed}: {str(exc).splitlines()[0]}")
        if len(html) > MAX_DOM_CHARS:
            html = html[:MAX_DOM_CHARS]
            dom_capped = True
            self.failures.append(f"dom {seed}: truncated at {MAX_DOM_CHARS} chars")

        cookies: list[dict[str, Any]] = []
        try:
            for cookie in context.cookies():
                cookies.append(
                    {
                        "name": cookie.get("name"),
                        "value": "<redacted>",
                        "domain": cookie.get("domain"),
                        "path": cookie.get("path"),
                        "secure": cookie.get("secure"),
                        "httpOnly": cookie.get("httpOnly"),
                        "sameSite": cookie.get("sameSite"),
                    }
                )
        except playwright_error:
            pass

        forms: list[dict[str, str]] = []
        storage: dict[str, list[str]] = {}
        try:
            forms = page.eval_on_selector_all(
                "form",
                "els => els.slice(0, 25).map(e => ({action: e.getAttribute('action') || '',"
                " method: (e.getAttribute('method') || 'get').toLowerCase()}))",
            )
            storage = page.evaluate(
                "() => ({local: Object.keys(localStorage), session: Object.keys(sessionStorage)})"
            )
        except playwright_error:
            pass

        title = ""
        try:
            title = page.title()
        except playwright_error:
            pass

        proxy_blocked = proxy.blocked[blocked_before:]
        if not html and navigation_error:
            context.close()
            reason = proxy_blocked[0]["reason"] if proxy_blocked else navigation_error
            self.store.capture(
                kind="blocked",
                url=seed,
                source=self.name,
                notes={"reason": reason, "proxy_blocked": proxy_blocked},
            )
            return None

        record = self.store.capture(
            kind="browser",
            url=seed,
            status=status,
            response_headers={},
            body=html,
            truncated=dom_capped,
            source=self.name,
            notes={
                "title": title,
                "requests": requests,
                "console": console,
                "cookies": cookies,
                "forms": forms,
                "storage": {key: list(value)[:25] for key, value in storage.items()},
                "navigation_error": navigation_error,
                "final_url": final_url,
                "proxy_blocked": proxy_blocked,
                "browser": self.browser_name,
            },
        )
        context.close()
        return record

    def normalize(self, records: list[EvidenceRecord]) -> list[Finding]:
        findings: list[Finding] = []
        for record in records:
            if record.kind != "browser":
                continue
            findings.extend(
                analyze_browser(record, profile=self.engagement.profile.value, now=time.time())
            )
        return findings


def _origin(url: str) -> str:
    parts = urlsplit(url)
    default = 443 if parts.scheme == "https" else 80
    host = parts.hostname or ""
    return (
        f"{parts.scheme}://{host}"
        if (parts.port or default) == default
        else (f"{parts.scheme}://{host}:{parts.port}")
    )
