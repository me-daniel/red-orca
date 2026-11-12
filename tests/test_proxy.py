"""The proxy, not the request interceptor, decides what leaves the machine.

Playwright follows a server-side redirect itself and opens the connection
before the route handler is asked, so these tests assert on the off-list
origin's own request log, not on a blocked-request list.
"""

from __future__ import annotations

import http.client
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest

from vsw.adapters.browser import BrowserAdapter
from vsw.adapters.proxy import GuardedProxy
from vsw.evidence import EvidenceStore
from vsw.scope import ScopeGuard, load_engagement


def proxy_get(proxy: GuardedProxy, url: str, method: str = "GET") -> tuple[int, bytes]:
    host, port = proxy.url.removeprefix("http://").split(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        connection.request(method, url)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


@pytest.fixture
def guard(manifest) -> ScopeGuard:
    return ScopeGuard(load_engagement(manifest()))


def test_in_scope_request_is_forwarded(guard: ScopeGuard, lab_server: str) -> None:
    with GuardedProxy(guard) as proxy:
        status, body = proxy_get(proxy, f"{lab_server}/vuln/echo?q=proxy-ok")
    assert status == 200
    assert b"proxy-ok" in body
    assert guard.requests == 1
    assert proxy.blocked == []


def test_off_list_origin_is_refused_without_connecting(
    guard: ScopeGuard, offlist_server: dict
) -> None:
    with GuardedProxy(guard) as proxy:
        status, body = proxy_get(proxy, f"{offlist_server['url']}/steal")
    assert status == 403
    assert b"origin" in body
    assert offlist_server["hits"] == []
    assert proxy.blocked and proxy.blocked[0]["url"].endswith("/steal")
    assert guard.blocked[0]["kind"] == "proxy"


def test_https_tunnelling_is_refused(guard: ScopeGuard) -> None:
    with GuardedProxy(guard) as proxy:
        status, _ = proxy_get(proxy, "example.invalid:443", method="CONNECT")
    assert status == 403
    assert guard.blocked and guard.blocked[0]["kind"] == "proxy"
    assert "tunnel" in guard.blocked[0]["reason"]


def test_path_outside_the_prefixes_is_refused(guard: ScopeGuard, lab_server: str) -> None:
    with GuardedProxy(guard) as proxy:
        status, _ = proxy_get(proxy, f"{lab_server}/robots.txt")
    assert status == 403
    assert "not approved" in proxy.blocked[0]["reason"]


OFFLIST_ROUTES = (
    "/vuln/open-redirect?to={target}",
    "/vuln/offlist-meta?to={target}",
    "/vuln/offlist-js?to={target}",
    "/vuln/offlist-iframe?to={target}",
)


@pytest.mark.parametrize("route", OFFLIST_ROUTES)
def test_browser_never_connects_to_an_off_list_origin(
    route: str,
    tmp_path: Path,
    manifest,
    lab_server: str,
    offlist_server: dict,
) -> None:
    target = f"{offlist_server['url']}/steal"
    engagement = load_engagement(manifest())
    guard = ScopeGuard(engagement)
    store = EvidenceStore(tmp_path / "evidence")
    adapter = BrowserAdapter(guard=guard, store=store, engagement=engagement, timeout_ms=8000)

    seed = f"{lab_server}{route.format(target=quote(target, safe=':/'))}"
    records = adapter.execute(adapter.plan([seed]))

    assert offlist_server["hits"] == [], f"{route} reached the off-list origin"
    assert any(target.split("/steal")[0] in item["url"] for item in guard.blocked), guard.blocked
    # Evidence still records what was observed, and says what was stopped.
    assert records
    notes = records[0].notes
    assert notes["proxy_blocked"] or any(item.get("blocked") for item in notes["requests"])


def test_non_chromium_engine_is_refused(manifest, tmp_path: Path) -> None:
    from vsw.adapters.base import AdapterUnavailable

    engagement = load_engagement(manifest())
    adapter = BrowserAdapter(
        guard=ScopeGuard(engagement),
        store=EvidenceStore(tmp_path / "evidence"),
        engagement=engagement,
        browser_name="webkit",
    )
    with pytest.raises(AdapterUnavailable) as exc:
        adapter.validate_config()
    assert "redirect hops" in str(exc.value)


def test_proxy_connects_to_the_checked_address(manifest, lab_server, monkeypatch) -> None:
    port = int(urlsplit(lab_server).port or 80)
    guard = ScopeGuard(
        load_engagement(manifest(origin=f"http://rebind.test:{port}")),
        resolver=lambda host, _: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    real = socket.getaddrinfo

    def no_rebind(host, *args, **kwargs):
        if host == "rebind.test":
            raise OSError("hostname was resolved again after the scope check")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", no_rebind)
    with GuardedProxy(guard) as proxy:
        status, body = proxy_get(proxy, f"http://rebind.test:{port}/vuln/echo?q=pinned-ok")
    assert status == 200
    assert b"pinned-ok" in body


def test_proxy_refuses_a_mutation_the_manifest_did_not_approve(manifest, lab_server) -> None:
    guard = ScopeGuard(load_engagement(manifest(methods=["GET", "POST"])))
    with GuardedProxy(guard) as proxy:
        status, _ = proxy_get(proxy, f"{lab_server}/vuln/action", method="POST")
    assert status == 403
    assert "changes state" in proxy.blocked[0]["reason"]
    assert guard.requests == 0


def test_proxy_enforces_the_manifest_concurrency_limit(manifest) -> None:
    state = {"active": 0, "peak": 0}
    lock = threading.Lock()

    class SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            time.sleep(0.25)
            body = b"slow"
            with lock:
                state["active"] -= 1
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        guard = ScopeGuard(
            load_engagement(manifest(origin=f"http://127.0.0.1:{port}", max_concurrency=1))
        )
        with GuardedProxy(guard) as proxy:
            results: list[tuple[int, bytes]] = []
            workers = [
                threading.Thread(
                    target=lambda: results.append(
                        proxy_get(proxy, f"http://127.0.0.1:{port}/vuln/")
                    )
                )
                for _ in range(2)
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=10)
        assert [status for status, _ in results] == [200, 200]
        assert state["peak"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
