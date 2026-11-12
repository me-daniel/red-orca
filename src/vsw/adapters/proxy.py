"""Guarded forward proxy for browser observation.

Playwright's request interceptor does not see server-side redirect hops: the
browser follows them itself and opens the connection first. That makes the
interceptor a filter, not an enforcement point. This proxy sits between the
browser and the network, so every connection, including redirect hops, meta
refreshes, script navigations, and iframes, is checked before it is opened.

The proxy binds a loopback port, refuses anything that is not an absolute
`http://` URL, and defers the scope decision to `ScopeGuard`. HTTPS is refused
rather than tunnelled, because a tunnel cannot be path-checked.
"""

from __future__ import annotations

import http.client
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self
from urllib.parse import urlsplit

from ..scope import ScopeDenied, ScopeGuard

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
ORIGIN_TIMEOUT = 20.0

# Framing headers belong to this hop, not the origin's connection.
HOP_BY_HOP = {
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class GuardedProxy:
    """A loopback forward proxy whose every connection passes the scope guard."""

    def __init__(self, guard: ScopeGuard) -> None:
        self.guard = guard
        self.blocked: list[dict[str, str]] = []
        self.errors: list[str] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.daemon_threads = True
        # The browser opens connections in parallel; the manifest's concurrency
        # limit has to govern them, not the adapter's intent.
        self._slots = threading.BoundedSemaphore(max(1, int(guard.engagement.max_concurrency)))
        self._server.proxy = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="vsw-proxy", daemon=True
        )

    @property
    def url(self) -> str:
        address = self._server.server_address
        return f"http://{address[0]!s}:{int(address[1])}"

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    # -- decisions --------------------------------------------------------
    def deny(self, handler: BaseHTTPRequestHandler, url: str, reason: str) -> None:
        self.blocked.append({"method": handler.command, "url": url, "reason": reason})
        self.guard.record_blocked("proxy", url, reason)
        _respond(handler, 403, f"blocked by scope guard: {reason}".encode())

    def handle(self, handler: BaseHTTPRequestHandler) -> None:
        with self._slots:
            self._handle(handler)

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        url = handler.path
        method = handler.command
        if not url.startswith(("http://", "https://")):
            return self.deny(handler, url, "proxy expects an absolute http(s) URL")
        if urlsplit(url).scheme != "http":
            return self.deny(handler, url, "https is not proxied; refusing to tunnel")
        try:
            target = self.guard.authorize(url, method)
        except ScopeDenied as exc:
            return self.deny(handler, url, exc.reason)

        self.guard.wait_for_rate(target.origin)
        body = _request_body(handler)
        path = target_uri(url)
        headers = {
            name: value for name, value in handler.headers.items() if name.lower() not in HOP_BY_HOP
        }
        # Connect to the address the guard checked, never to a fresh lookup.
        headers["Host"] = target.host_header
        try:
            connection = http.client.HTTPConnection(
                target.address, target.port, timeout=ORIGIN_TIMEOUT
            )
            try:
                connection.request(method, path, body=body or None, headers=headers)
                response = connection.getresponse()
                payload = response.read(MAX_RESPONSE_BYTES)
                self._relay(handler, response, payload)
            finally:
                connection.close()
        except OSError as exc:
            reason = f"{method} {url}: {exc}"
            self.errors.append(reason)
            _respond(handler, 502, reason.encode())

    def _relay(
        self, handler: BaseHTTPRequestHandler, response: http.client.HTTPResponse, payload: bytes
    ) -> None:
        handler.send_response(response.status, response.reason)
        for name, value in response.getheaders():
            if name.lower() not in HOP_BY_HOP:
                handler.send_header(name, value)
        handler.send_header("Content-Length", str(len(payload)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(payload)
        handler.close_connection = True


class _Handler(BaseHTTPRequestHandler):
    server_version = "vsw-guard"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # keep the adapter output quiet
        pass

    def _dispatch(self) -> None:
        self.server.proxy.handle(self)  # type: ignore[attr-defined]

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _dispatch

    def do_CONNECT(self) -> None:
        self.server.proxy.deny(  # type: ignore[attr-defined]
            self, self.path, "https is not proxied; refusing to tunnel"
        )


def target_uri(url: str) -> str:
    """Origin-form request target for an absolute URL."""
    parts = urlsplit(url)
    target = parts.path or "/"
    return f"{target}?{parts.query}" if parts.query else target


def _request_body(handler: BaseHTTPRequestHandler) -> bytes:
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except ValueError:
        return b""
    if length <= 0:
        return b""
    return handler.rfile.read(min(length, MAX_RESPONSE_BYTES))


def _respond(handler: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    handler.close_connection = True
