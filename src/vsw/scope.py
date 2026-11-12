"""Engagement manifests and externally enforced scope.

The model never widens scope. Every request an adapter makes, including
redirect hops and browser subresources, passes through `ScopeGuard`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

from .domain import Engagement, Profile
from .util import utc_now


class ScopeError(RuntimeError):
    """The engagement cannot be used as supplied."""


class ScopeDenied(ScopeError):
    """A specific operation falls outside the approved scope."""

    status = "blocked"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def canonical_manifest(engagement: Engagement) -> str:
    """Canonical form hashed for approval. Excludes the approval block itself."""
    data = engagement.model_dump(mode="json")
    data.pop("approval", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_hash(engagement: Engagement) -> str:
    return hashlib.sha256(canonical_manifest(engagement).encode("utf-8")).hexdigest()


def load_engagement(path: Path) -> Engagement:
    if not path.exists():
        raise ScopeError(f"engagement manifest not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ScopeError(f"{path} must contain a mapping")
    return validate_engagement(Engagement.model_validate(raw))


def validate_engagement(engagement: Engagement) -> Engagement:
    """Reject unusable manifests before any request is made."""
    if engagement.profile not in {Profile.LAB, Profile.OBSERVE}:
        raise ScopeError(f"profile {engagement.profile.value} is not enabled; use lab or observe")
    if not engagement.origins:
        raise ScopeError("manifest lists no origins")
    for origin in engagement.origins:
        parts = urlsplit(origin)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ScopeError(f"origin must be an absolute http(s) URL: {origin}")
        if parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise ScopeError(f"origin must not include a path or query: {origin}")
    if not engagement.methods:
        raise ScopeError("manifest lists no methods")
    for method in engagement.methods:
        if method != method.upper():
            raise ScopeError(f"methods must be uppercase: {method}")
    if not engagement.approval.approved:
        raise ScopeError("engagement is not approved; a human must approve the manifest")
    expected = engagement.approval.approved_manifest_sha256
    actual = manifest_hash(engagement)
    if not expected:
        raise ScopeError("approval has no manifest hash; run `vsw engagement approve` after review")
    if expected != actual:
        raise ScopeError(
            "approval does not match the manifest; material changes require re-approval"
        )
    return engagement


def approve_manifest(path: Path, approver: str) -> Engagement:
    """Record human approval over the current manifest content."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    engagement = Engagement.model_validate(raw)
    engagement = engagement.model_copy(
        update={
            "approval": engagement.approval.model_copy(
                update={
                    "approved": True,
                    "approved_by": approver,
                    "approved_at": utc_now(),
                    "approved_manifest_sha256": manifest_hash(engagement),
                }
            )
        }
    )
    data = engagement.model_dump(mode="json")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return engagement


def _is_local_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_loopback


def _is_private_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _under(path: str, prefix: str) -> bool:
    """Segment-boundary prefix match.

    `/vuln` covers `/vuln` and `/vuln/x`, never `/vulnerability`.
    """
    base = prefix.rstrip("/")
    if not base:
        return True
    return path == base or path.startswith(base + "/")


def _path_candidates(path: str) -> set[str]:
    """Every plausible reading of a request path.

    Servers decode and normalize before routing, so a path that only passes the
    raw check is not enough: `/vuln/../admin` and `/vuln/%64elete` must be read
    the way the target would read them.
    """
    raw = path or "/"
    decoded = unquote(raw)
    return {raw, decoded, posixpath.normpath(raw), posixpath.normpath(decoded)}


@dataclass(frozen=True)
class PinnedTarget:
    """An authorized request whose connection address is already decided.

    Adapters must connect to `address`, not re-resolve `host`: a hostname can
    answer with one address for the check and another for the connection.
    """

    scheme: str
    host: str
    port: int
    address: str
    origin: str

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    @property
    def url_host(self) -> str:
        return f"[{self.address}]" if ":" in self.address else self.address


class ScopeGuard:
    """Gate every destination, method, path, and budget check."""

    def __init__(
        self,
        engagement: Engagement,
        now: float | None = None,
        resolver: Any = None,
    ) -> None:
        # Re-validate here: a caller may hand over an object that was never
        # loaded through `load_engagement`, and approval must bind to content.
        self.engagement = validate_engagement(engagement)
        self.started = now if now is not None else time.monotonic()
        self.resolver = resolver or socket.getaddrinfo
        self._lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self.requests = 0
        self.blocked: list[dict[str, str]] = []
        self.stop_reason = ""
        self._last_request: dict[str, float] = {}
        self._address_cache: dict[str, list[str]] = {}

    # -- helpers ---------------------------------------------------------
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def protocol(self) -> str:
        return "http"

    def _origin_of(self, parts: Any) -> str:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        default = 443 if parts.scheme == "https" else 80
        host = parts.hostname or ""
        return f"{parts.scheme}://{host}" if port == default else f"{parts.scheme}://{host}:{port}"

    def _approved_origin(self, origin: str) -> bool:
        for approved in self.engagement.origins:
            parts = urlsplit(approved)
            if self._origin_of(parts) == origin or approved.rstrip("/") == origin:
                return True
        return False

    def resolve(self, host: str) -> list[str]:
        if host in self._address_cache:
            return self._address_cache[host]
        try:
            infos = self.resolver(host, None)
        except OSError as exc:
            raise ScopeDenied(f"cannot resolve {host}: {exc}") from exc
        addresses: list[str] = []
        for info in infos:
            address = str(info[4][0])
            if address not in addresses:
                addresses.append(address)
        self._address_cache[host] = addresses
        return addresses

    # -- checks ----------------------------------------------------------
    def authorize(self, url: str, method: str = "GET", reserve: bool = True) -> PinnedTarget:
        """Raise ScopeDenied unless this exact request is allowed right now.

        Returns the address the connection must use. A passing check reserves
        one request from the budget atomically, so a request can never be
        dispatched beyond `max_requests`. Pass `reserve=False` for a pre-flight
        check that will not send anything.
        """
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ScopeDenied(f"not an absolute http(s) URL: {url}")
        # Browsers, proxies, and servers disagree about these; refuse rather
        # than guess which destination a request would actually reach.
        if "\\" in url:
            raise ScopeDenied(f"backslash in URL is ambiguous: {url}")
        if parts.username is not None or parts.password is not None:
            raise ScopeDenied(f"credentials in URL are not allowed: {url}")
        upper = method.upper()
        if upper not in self.engagement.methods:
            raise ScopeDenied(f"method {upper} is not approved")
        # A page can issue any approved method on its own. Mutations stay off
        # unless the manifest says otherwise, whatever the adapter planned.
        if not self.engagement.mutation_allowed and upper not in SAFE_METHODS:
            raise ScopeDenied(f"method {upper} changes state and mutation is not approved")
        origin = self._origin_of(parts)
        if not self._approved_origin(origin):
            raise ScopeDenied(f"origin {origin} is not approved")
        for path in _path_candidates(parts.path):
            if self.engagement.exclude_paths and any(
                _under(path, prefix) for prefix in self.engagement.exclude_paths
            ):
                raise ScopeDenied(f"path {path} is excluded")
            if not any(_under(path, prefix) for prefix in self.engagement.path_prefixes):
                raise ScopeDenied(f"path {path} is not approved")
        if self.expired():
            raise ScopeDenied("engagement has expired")
        addresses = self.resolve(parts.hostname)
        if not addresses:
            raise ScopeDenied(f"{parts.hostname} resolved to no addresses")
        for address in addresses:
            if self.engagement.profile is Profile.LAB:
                if not _is_local_address(address):
                    raise ScopeDenied(
                        f"lab profile only reaches loopback; {parts.hostname} -> {address}"
                    )
            elif _is_private_address(address):
                raise ScopeDenied(
                    f"observe profile must not reach private addresses; "
                    f"{parts.hostname} -> {address}"
                )
        with self._lock:
            if self.requests >= self.engagement.max_requests:
                self.stop_reason = "request limit reached"
                raise ScopeDenied(
                    f"request limit reached: {self.requests} >= {self.engagement.max_requests}"
                )
            if self.elapsed() >= self.engagement.max_wall_seconds:
                self.stop_reason = "wall-clock limit reached"
                raise ScopeDenied(
                    f"wall-clock limit reached: {self.elapsed():.0f}s >= "
                    f"{self.engagement.max_wall_seconds:.0f}s"
                )
            if reserve:
                self.requests += 1
        default_port = 443 if parts.scheme == "https" else 80
        return PinnedTarget(
            scheme=parts.scheme,
            host=parts.hostname,
            port=parts.port or default_port,
            address=addresses[0],
            origin=origin,
        )

    def check(self, url: str, method: str = "GET", reserve: bool = True) -> None:
        """Authorization without the pin, for callers that only need a verdict."""
        self.authorize(url, method, reserve)

    def expired(self) -> bool:
        try:
            return utc_now() > self.engagement.expires_at
        except TypeError:
            return True

    def wait_for_rate(self, origin: str) -> None:
        """One request per origin at most every 1/max_rps seconds.

        The proxy handles requests on several threads, so the slot is taken
        under a lock; two connections cannot both read the same last-send time.
        """
        interval = 1.0 / self.engagement.max_rps if self.engagement.max_rps > 0 else 0.0
        with self._rate_lock:
            last = self._last_request.get(origin)
            if last is not None:
                remaining = interval - (time.monotonic() - last)
                if remaining > 0:
                    time.sleep(min(remaining, 5.0))
            self._last_request[origin] = time.monotonic()

    def record_blocked(self, kind: str, url: str, reason: str) -> None:
        self.blocked.append({"kind": kind, "url": url, "reason": reason})

    def remaining_requests(self) -> int:
        with self._lock:
            return max(0, self.engagement.max_requests - self.requests)

    def summary(self) -> dict[str, object]:
        return {
            "engagement": self.engagement.id,
            "profile": self.engagement.profile.value,
            "manifest_sha256": manifest_hash(self.engagement),
            "requests": self.requests,
            "request_limit": self.engagement.max_requests,
            "blocked": list(self.blocked),
            "stop_reason": self.stop_reason,
        }
