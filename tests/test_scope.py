import time
from pathlib import Path

import pytest
import yaml

from vsw.domain import Profile
from vsw.scope import (
    ScopeDenied,
    ScopeError,
    ScopeGuard,
    approve_manifest,
    load_engagement,
    manifest_hash,
)


def _write(path: Path, origin: str = "http://127.0.0.1:8787", **overrides) -> Path:
    data = {
        "id": "unit",
        "owner": "tester",
        "approver": "tester",
        "authorization_ref": "unit test",
        "profile": "lab",
        "expires_at": "2030-01-01T00:00:00Z",
        "origins": [origin],
        "methods": ["GET"],
        "path_prefixes": ["/vuln"],
        "exclude_paths": ["/vuln/delete"],
        "mutation_allowed": False,
        "max_requests": 5,
        "max_rps": 50.0,
        "max_wall_seconds": 60,
        "max_concurrency": 1,
        "approval": {
            "approved": False,
            "approved_by": None,
            "approved_at": None,
            "approved_manifest_sha256": None,
        },
    }
    data.update(overrides)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def test_unapproved_manifest_is_rejected(tmp_path):
    path = _write(tmp_path / "m.yaml")
    with pytest.raises(ScopeError, match="not approved"):
        load_engagement(path)


def test_edited_manifest_invalidates_approval(tmp_path):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    assert load_engagement(path).id == "unit"

    data = yaml.safe_load(path.read_text())
    data["origins"] = ["http://127.0.0.1:9999"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(ScopeError, match="does not match"):
        load_engagement(path)


def test_approval_hash_ignores_the_approval_block(tmp_path):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    first = manifest_hash(load_engagement(path))
    approve_manifest(path, "someone-else")
    second = manifest_hash(load_engagement(path))
    assert first == second


def test_expired_manifest_is_denied(tmp_path):
    path = _write(tmp_path / "m.yaml", expires_at="2020-01-01T00:00:00Z")
    approve_manifest(path, "tester")
    engagement = load_engagement(path)
    guard = ScopeGuard(engagement, resolver=lambda host, _: [(2, 1, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(ScopeDenied, match="expired"):
        guard.check("http://127.0.0.1:8787/vuln/")


def test_out_of_scope_origin_is_denied(tmp_path):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    guard = ScopeGuard(load_engagement(path))
    with pytest.raises(ScopeDenied, match="not approved"):
        guard.check("http://127.0.0.1:8788/vuln/")
    with pytest.raises(ScopeDenied, match="not approved"):
        guard.check("https://example.invalid/vuln/")


def test_excluded_path_and_method_are_denied(tmp_path):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    guard = ScopeGuard(load_engagement(path))
    with pytest.raises(ScopeDenied, match="excluded"):
        guard.check("http://127.0.0.1:8787/vuln/delete")
    with pytest.raises(ScopeDenied, match="not approved"):
        guard.check("http://127.0.0.1:8787/other")
    with pytest.raises(ScopeDenied, match="method"):
        guard.check("http://127.0.0.1:8787/vuln/", "POST")


def test_lab_profile_refuses_non_loopback_addresses(tmp_path):
    path = _write(tmp_path / "m.yaml", origins=["http://internal.example"])
    approve_manifest(path, "tester")
    guard = ScopeGuard(
        load_engagement(path),
        resolver=lambda host, _: [(2, 1, 6, "", ("10.1.2.3", 0))],
    )
    with pytest.raises(ScopeDenied, match="loopback"):
        guard.check("http://internal.example/vuln/")


def test_observe_profile_refuses_private_addresses(tmp_path):
    path = _write(tmp_path / "m.yaml", profile="observe", origins=["http://internal.example"])
    approve_manifest(path, "tester")
    guard = ScopeGuard(
        load_engagement(path),
        resolver=lambda host, _: [(2, 1, 6, "", ("192.168.1.10", 0))],
    )
    with pytest.raises(ScopeDenied, match="private"):
        guard.check("http://internal.example/vuln/")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8787/vuln/../admin",
        "http://127.0.0.1:8787/vuln/%2e%2e/admin",
        "http://127.0.0.1:8787/vuln/%64elete",
        "http://127.0.0.1:8787//vuln/",
        "http://127.0.0.1:8787/vuln/../../etc/passwd",
    ],
)
def test_ambiguous_paths_are_denied(tmp_path, url):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    guard = ScopeGuard(load_engagement(path))
    with pytest.raises(ScopeDenied):
        guard.check(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example\\@127.0.0.1:8787/vuln/",
        "http://user:pass@127.0.0.1:8787/vuln/",
    ],
)
def test_ambiguous_authorities_are_denied(tmp_path, url):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    guard = ScopeGuard(load_engagement(path))
    with pytest.raises(ScopeDenied):
        guard.check(url)


def test_denied_request_does_not_consume_budget(tmp_path):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    guard = ScopeGuard(
        load_engagement(path),
        resolver=lambda host, _: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(ScopeDenied):
        guard.check("http://127.0.0.1:8787/other")
    assert guard.remaining_requests() == 5


def test_request_limit_is_enforced(tmp_path):
    path = _write(tmp_path / "m.yaml")
    approve_manifest(path, "tester")
    guard = ScopeGuard(
        load_engagement(path),
        resolver=lambda host, _: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    for _ in range(5):
        guard.check("http://127.0.0.1:8787/vuln/")
    with pytest.raises(ScopeDenied, match="request limit"):
        guard.check("http://127.0.0.1:8787/vuln/")


def test_wall_clock_limit_is_enforced(tmp_path):
    path = _write(tmp_path / "m.yaml", max_wall_seconds=0)
    approve_manifest(path, "tester")
    guard = ScopeGuard(load_engagement(path), now=time.monotonic() - 5)
    with pytest.raises(ScopeDenied, match="wall-clock"):
        guard.check("http://127.0.0.1:8787/vuln/")


def test_profile_must_be_supported(tmp_path):
    path = _write(tmp_path / "m.yaml", profile="production-validate")
    path.write_text(
        path.read_text().replace(
            "approved_manifest_sha256: null", "approved_manifest_sha256: deadbeef"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ScopeError, match="not enabled"):
        load_engagement(path)


def test_manifest_hash_is_stable_across_reload(tmp_path):
    path = _write(tmp_path / "m.yaml")
    engagement = approve_manifest(path, "tester")
    assert manifest_hash(engagement) == manifest_hash(load_engagement(path))
    assert engagement.profile is Profile.LAB
