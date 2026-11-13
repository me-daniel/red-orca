"""Inert validation uses real lab traffic and deterministic HTTP transports."""

from contextlib import contextmanager
from dataclasses import replace
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from vsw.adapters.passive_http import PassiveHttpAdapter
from vsw.adapters.validation import REDIRECT_MARKER, ValidationAdapter
from vsw.domain import Confidence, FindingState, Profile, Severity
from vsw.evidence import MAX_BODY_BYTES, EvidenceStore
from vsw.reproduction import verify_reproduction
from vsw.scope import ScopeDenied, ScopeGuard, load_engagement, manifest_hash


def adapter(tmp_path, manifest, checks=("html-injection",), **manifest_options):
    engagement = load_engagement(manifest(**manifest_options))
    guard = ScopeGuard(engagement)
    return ValidationAdapter(guard, EvidenceStore(tmp_path / "run"), engagement, list(checks))


def stub_http(monkeypatch, handler):
    calls = []

    @contextmanager
    def stream(method, url, **kwargs):
        assert kwargs.pop("trust_env") is False
        assert kwargs["follow_redirects"] is False
        assert 0 < kwargs["timeout"] <= 10
        calls.append((method, url))
        with (
            httpx.Client(transport=httpx.MockTransport(handler), trust_env=False) as client,
            client.stream(method, url, **kwargs) as response,
        ):
            yield response

    monkeypatch.setattr(httpx, "stream", stream)
    return calls


@pytest.mark.parametrize(
    "check,path,cwe",
    [
        ("html-injection", "/vuln/echo", "CWE-79"),
        ("open-redirect", "/vuln/open-redirect", "CWE-601"),
    ],
)
def test_real_pinned_positive(tmp_path, manifest, lab_server, check, path, cwe):
    a = adapter(tmp_path, manifest, [check])
    plan = a.plan([lab_server + path + "?keep=a%26b&q=old&to=old"])
    assert plan.methods == ["GET"] and not plan.mutations
    assert plan.cleanup == "none" and plan.estimated_requests == 1
    query = parse_qs(urlsplit(plan.destinations[0]).query)
    assert query["keep"] == ["a&b"]
    if check == "html-injection":
        assert query["to"] == ["old"] and query["q"][0].startswith("<vsw-check-")
    else:
        assert query["q"] == ["old"] and query["to"] == [REDIRECT_MARKER]
    records = a.execute(plan)
    findings = a.normalize(records)
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.severity, finding.confidence, finding.state) == (
        Severity.MEDIUM,
        Confidence.HIGH,
        FindingState.VALIDATED,
    )
    assert finding.cwe == cwe and finding.remediation and finding.limitations
    assert finding.evidence_ids == finding.exchange_ids == [records[0].id]
    assert finding.first_seen == finding.last_seen == records[0].captured_at != ""
    assert finding.regression_recipe
    assert ("q" if check == "html-injection" else "to=") in " ".join(finding.regression_recipe)
    assert verify_reproduction(
        finding.reproduction_detail, {r["id"]: r for r in a.store.exchanges()}
    ).verified
    assert a.guard.requests == 1 and len(records) == 1
    assert records[0].notes["peer"] == "127.0.0.1"
    assert not a.store.verify()
    if check == "html-injection":
        assert finding.title == "HTML injection"
        assert "No JavaScript execution or session impact tested" in finding.limitations


def test_redacted_query_parameters_do_not_break_normalization(
    tmp_path, manifest, lab_server
):
    a = adapter(tmp_path, manifest)
    plan = a.plan([lab_server + "/vuln/echo?token=supersecretvalue&q=hello"])
    records = a.execute(plan)
    assert len(records) == 1
    assert "supersecretvalue" not in records[0].url
    assert "supersecretvalue" not in records[0].request_text
    findings = a.normalize(records)
    assert len(findings) == 1
    assert findings[0].check_id == "html-injection"
    assert findings[0].state == FindingState.VALIDATED
    assert verify_reproduction(
        findings[0].reproduction_detail, {record["id"]: record for record in a.store.exchanges()}
    ).verified


@pytest.mark.parametrize(
    "context",
    [
        "escaped",
        "comment",
        "script",
        "style",
        "textarea",
        "title",
        "xmp",
        "iframe",
        "noembed",
        "noframes",
        "plaintext",
        "template",
        "noscript",
        "nested-raw",
        "raw-fake-close",
        "self-closing-raw",
    ],
)
def test_html_inert_contexts(tmp_path, manifest, lab_server, monkeypatch, context):
    a = adapter(tmp_path, manifest)

    def respond(request):
        marker = request.url.params["q"]
        if context == "escaped":
            body = escape(marker)
        elif context == "comment":
            body = f"<!-- {marker} -->"
        elif context == "nested-raw":
            body = f"<template><textarea></template>{marker}</textarea></template>"
        elif context == "raw-fake-close":
            body = f"<textarea><x title='</textarea>'>{marker}</textarea>"
            # HTML raw text really ends at the first </textarea>, even in quotes.
            # Use a different fake closing tag to test the raw parser boundary.
            body = f"<textarea></title>{marker}</textarea>"
        elif context == "self-closing-raw":
            body = f"<textarea/>{marker}"
        else:
            body = f"<{context}>{marker}</{context}>"
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text=body)

    calls = stub_http(monkeypatch, respond)
    records = a.execute(a.plan([lab_server + "/vuln/echo"]))
    assert len(calls) == 1 and not a.normalize(records)


def test_stub_positive_preserves_data_and_no_crawl(tmp_path, manifest, lab_server, monkeypatch):
    a = adapter(tmp_path, manifest)

    def respond(request):
        assert request.headers["host"] == urlsplit(lab_server).netloc
        assert request.url.params["other"] == "<script>data</script>"
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text=request.url.params["q"] + '<a href="/vuln/echo">link</a>',
        )

    calls = stub_http(monkeypatch, respond)
    records = a.execute(a.plan([lab_server + "/vuln/echo?other=%3Cscript%3Edata%3C/script%3E"]))
    assert len(a.normalize(records)) == len(calls) == 1


@pytest.mark.parametrize(
    "status,location",
    [
        (200, REDIRECT_MARKER),
        (302, "/clean/"),
        (302, REDIRECT_MARKER + "/"),
        (503, REDIRECT_MARKER),
    ],
)
def test_redirect_controls(tmp_path, manifest, lab_server, monkeypatch, status, location):
    a = adapter(tmp_path, manifest, ["open-redirect"])
    calls = stub_http(
        monkeypatch,
        lambda request: httpx.Response(status, headers={"location": location}, text="control"),
    )
    records = a.execute(a.plan([lab_server + "/vuln/open-redirect"]))
    assert not a.normalize(records) and len(calls) == 1


def test_never_follow_offlist(tmp_path, manifest, lab_server, offlist_server, monkeypatch):
    a = adapter(tmp_path, manifest, ["open-redirect"])
    calls = stub_http(
        monkeypatch,
        lambda request: httpx.Response(302, headers={"location": offlist_server["url"]}),
    )
    assert not a.normalize(a.execute(a.plan([lab_server + "/vuln/open-redirect"])))
    assert len(calls) == 1 and offlist_server["hits"] == []


@pytest.mark.parametrize("checks", [[], ["unknown"], ["html-injection", "html-injection"]])
def test_checks_denied(tmp_path, manifest, checks):
    with pytest.raises(ScopeDenied):
        adapter(tmp_path, manifest, checks)


@pytest.mark.parametrize(
    "case",
    [
        "excluded",
        "https",
        "remote",
        "non-lab",
        "method",
        "mismatch",
        "unapproved",
        "expired",
        "invalid-expiry",
    ],
)
def test_configuration_and_scope_denied(tmp_path, manifest, lab_server, case):
    options = {"exclude_paths": ["/vuln/echo"]} if case == "excluded" else {}
    if case == "non-lab":
        options["profile"] = "observe"
    if case == "method":
        options["methods"] = ["HEAD"]
    if case == "https":
        options["origin"] = lab_server.replace("http:", "https:")
    if case == "remote":
        options["origin"] = "http://192.0.2.1"
    e = load_engagement(manifest(**options))
    guard = ScopeGuard(e)
    if case == "mismatch":
        e = e.model_copy(deep=True)
        e.id = "different"
        e.approval.approved_manifest_sha256 = manifest_hash(e)
    elif case == "unapproved":
        e.approval.approved = False
    elif case in {"expired", "invalid-expiry"}:
        e.expires_at = "2000-01-01T00:00:00Z" if case == "expired" else "nonsense"
        e.approval.approved_manifest_sha256 = manifest_hash(e)
    with pytest.raises(ScopeDenied):
        a = ValidationAdapter(guard, EvidenceStore(tmp_path / "run"), e, ["html-injection"])
        a.plan([e.origins[0] + "/vuln/echo"])
    assert guard.requests == 0


@pytest.mark.parametrize("seeds", [[], ["/vuln/echo"], ["one", "two"]])
def test_requires_one_explicit_target(tmp_path, manifest, seeds):
    a = adapter(tmp_path, manifest)
    with pytest.raises(ScopeDenied):
        a.plan(seeds)


@pytest.mark.parametrize(
    "field,value",
    [
        ("destinations", ["http://example.invalid/"]),
        ("methods", ["POST"]),
        ("mutations", True),
        ("estimated_requests", 99),
        ("cleanup", "delete"),
        ("adapter", "passive-http"),
    ],
)
def test_mutated_plan_denied_before_io(tmp_path, manifest, lab_server, monkeypatch, field, value):
    a = adapter(tmp_path, manifest)
    plan = a.plan([lab_server + "/vuln/echo"])
    setattr(plan, field, value)
    monkeypatch.setattr(a, "_stream", lambda *args: pytest.fail("unexpected I/O"))
    with pytest.raises(ScopeDenied):
        a.execute(plan)
    assert a.guard.requests == 0


def test_plan_once_and_unrecognized_copy(tmp_path, manifest, lab_server):
    a = adapter(tmp_path, manifest, ["html-injection", "open-redirect"])
    plan = a.plan([lab_server + "/vuln/echo"])
    assert plan.estimated_requests == len(plan.destinations) == 2
    with pytest.raises(ScopeDenied):
        a.plan([lab_server + "/vuln/echo"])
    with pytest.raises(ScopeDenied):
        a.execute(plan.model_copy(deep=True))


@pytest.mark.parametrize("change", ["approval", "expiry", "profile", "cancel", "budget", "pin"])
def test_recheck_after_rate_wait(tmp_path, manifest, lab_server, monkeypatch, change):
    a = adapter(tmp_path, manifest)
    plan = a.plan([lab_server + "/vuln/echo"])

    def wait(origin):
        if change == "approval":
            a.engagement.approval.approved = False
        elif change == "expiry":
            a.engagement.expires_at = "2000-01-01T00:00:00Z"
            a.engagement.approval.approved_manifest_sha256 = manifest_hash(a.engagement)
        elif change == "profile":
            a.engagement.profile = Profile.OBSERVE
            a.engagement.approval.approved_manifest_sha256 = manifest_hash(a.engagement)
        elif change == "cancel":
            a.cancel()
        elif change == "budget":
            a.guard.requests = a.engagement.max_requests
        else:
            a.guard._address_cache["127.0.0.1"] = ["192.0.2.1"]

    monkeypatch.setattr(a.guard, "wait_for_rate", wait)
    monkeypatch.setattr(a, "_stream", lambda *args: pytest.fail("unexpected I/O"))
    assert a.execute(plan) == []
    assert a.failures and a.guard.stop_reason
    assert a.guard.requests == (a.engagement.max_requests if change == "budget" else 0)


@pytest.mark.parametrize("stop", ["cancel", "budget", "wall"])
def test_stop_before_dispatch(tmp_path, manifest, lab_server, monkeypatch, stop):
    a = adapter(tmp_path, manifest)
    plan = a.plan([lab_server + "/vuln/echo"])
    if stop == "cancel":
        a.cancel()
    elif stop == "budget":
        a.guard.requests = a.engagement.max_requests
    else:
        a.guard.started -= a.engagement.max_wall_seconds
    monkeypatch.setattr(a, "_stream", lambda *args: pytest.fail("unexpected I/O"))
    assert a.execute(plan) == [] and a.failures and a.guard.stop_reason


@pytest.mark.parametrize("problem", ["capped", "unhealthy", "network", "late", "cancel"])
def test_incomplete_never_validates(tmp_path, manifest, lab_server, monkeypatch, problem):
    a = adapter(tmp_path, manifest)
    plan = a.plan([lab_server + "/vuln/echo"])

    def respond(request):
        marker = request.url.params["q"]
        if problem == "network":
            raise httpx.ReadError("broken connection")
        if problem == "late":
            a.guard.started -= a.engagement.max_wall_seconds
        if problem == "cancel":
            a.cancel()
        body = marker + ("x" * MAX_BODY_BYTES if problem == "capped" else "")
        return httpx.Response(
            503 if problem == "unhealthy" else 200, headers={"content-type": "text/html"}, text=body
        )

    calls = stub_http(monkeypatch, respond)
    records = a.execute(plan)
    assert len(calls) == a.guard.requests == 1
    assert not a.normalize(records)
    assert a.failures and a.guard.stop_reason
    if records:
        assert records[0].notes["complete"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "POST"),
        ("source", "passive-http"),
        ("body", "changed"),
        ("status", 500),
        ("url", "http://example.invalid/"),
    ],
)
def test_only_exact_captured_records_normalize(tmp_path, manifest, lab_server, field, value):
    a = adapter(tmp_path, manifest)
    records = a.execute(a.plan([lab_server + "/vuln/echo"]))
    assert len(a.normalize(records)) == 1
    assert not a.normalize([replace(records[0], **{field: value})])
    assert not a.normalize([replace(records[0], notes={**records[0].notes, "marker": "fake"})])


@pytest.mark.parametrize(
    "check,path,positive",
    [
        ("html-injection", "/vuln/echo", True),
        ("html-injection", "/clean/echo", False),
        ("open-redirect", "/vuln/open-redirect", True),
        ("open-redirect", "/clean/open-redirect", False),
    ],
)
def test_real_validation_pipeline(
    tmp_path, manifest, lab_server, monkeypatch, check, path, positive
):
    import json
    from pathlib import Path

    from vsw import orchestrator

    def forbidden(*args, **kwargs):
        pytest.fail("validation selected a passive or browser adapter")

    monkeypatch.setattr(orchestrator, "PassiveHttpAdapter", forbidden)
    monkeypatch.setattr(orchestrator, "BrowserAdapter", forbidden)
    report = orchestrator.run_observation(
        manifest(), lab_server + path, root=tmp_path, validation_checks=[check]
    )
    assert report["status"] == "pass"
    assert report["stage"] == "M2"
    assert report["evidence_integrity"] == []
    assert report["coverage"]["requests_made"] == 1
    assert report["coverage"]["stop_reason"] == ""
    assert [item["adapter"] for item in report["adapters"]] == ["validation"]
    assert len(report["findings"]) == int(positive)
    assert len(report["evidence"]) == 1
    if positive:
        finding = report["findings"][0]
        assert finding["check_id"] == check
        assert finding["state"] == "validated" and finding["reproduction_verified"]
        exchange = next(r for r in report["evidence"] if r["id"] == finding["exchange_ids"][0])
        assert finding["first_seen"] == finding["last_seen"] == exchange["captured_at"] != ""
        assert finding["regression_recipe"]
        from vsw.domain import Reproduction

        assert verify_reproduction(
            Reproduction.model_validate(finding["reproduction_detail"]),
            {r["id"]: r for r in report["evidence"]},
        ).verified
    run_dir = Path(report["run_dir"])
    assert EvidenceStore(run_dir).verify() == []
    exported = json.loads((run_dir / "findings.json").read_text())
    assert exported == {k: v for k, v in report.items() if k != "run_dir"}
    assert json.loads((run_dir / "coverage.json").read_text()) == report["coverage"]
    run = json.loads((run_dir / "run.json").read_text())
    assert run["validated"] == int(positive)
    assert len(json.loads((run_dir / "exchanges.json").read_text())["exchanges"]) == 1
    markdown = (run_dir / "report.md").read_text()
    assert "no payloads were sent" not in markdown
    assert "redirects were not followed" in markdown
    assert (
        "Reproduction (captured):" in markdown
        if positive
        else "No findings were produced" in markdown
    )


def test_real_cli_repeatable_checks(tmp_path, manifest, lab_server, monkeypatch):
    import json
    from pathlib import Path

    from typer.testing import CliRunner

    from vsw import cli, orchestrator

    monkeypatch.setattr(orchestrator, "repo_root", lambda: tmp_path)
    result = CliRunner().invoke(
        cli.app,
        [
            "validate",
            "--manifest",
            str(manifest()),
            "--target",
            lab_server + "/vuln/echo",
            "--check",
            "html-injection",
            "--check",
            "open-redirect",
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["status"] == "pass"
    assert summary["findings"] == summary["validated"] == 1
    assert summary["coverage"]["requests_made"] == 2
    assert summary["coverage"]["stop_reason"] == "completed"
    assert summary["evidence_integrity"] == []
    payload = json.loads(Path(summary["run_dir"], "findings.json").read_text())
    assert len(payload["evidence"]) == 2
    assert [item["adapter"] for item in payload["adapters"]] == ["validation"]


@pytest.mark.parametrize("checks", [[], ["unknown"], ["html-injection", "html-injection"]])
def test_pipeline_selection_fails_closed(tmp_path, manifest, lab_server, monkeypatch, checks):
    from vsw.orchestrator import run_observation
    from vsw.scope import ScopeError

    monkeypatch.setattr(PassiveHttpAdapter, "_stream", lambda *args: pytest.fail("unexpected I/O"))
    with pytest.raises((ScopeError, ValueError)):
        run_observation(
            manifest(), lab_server + "/vuln/echo", root=tmp_path, validation_checks=checks
        )


@pytest.mark.parametrize(
    "case", ["profile", "target", "missing-target", "many-targets", "fragment"]
)
def test_pipeline_preflight_no_io(tmp_path, manifest, lab_server, monkeypatch, case):
    from vsw.orchestrator import run_observation
    from vsw.scope import ScopeError

    monkeypatch.setattr(PassiveHttpAdapter, "_stream", lambda *args: pytest.fail("unexpected I/O"))
    kwargs = {"target": lab_server + "/vuln/echo"}
    if case == "target":
        kwargs["target"] = lab_server + "/outside"
    elif case == "fragment":
        kwargs["target"] += "#fragment"
    elif case == "missing-target":
        kwargs = {}
    elif case == "many-targets":
        kwargs = {"targets": [lab_server + "/vuln/echo", lab_server + "/clean/echo"]}
    with pytest.raises((ScopeError, ValueError)):
        run_observation(
            manifest(profile="observe" if case == "profile" else "lab"),
            root=tmp_path,
            validation_checks=["html-injection"],
            **kwargs,
        )


def test_default_passive_selection_unchanged(tmp_path, manifest, lab_server, monkeypatch):
    from vsw.adapters.browser import BrowserAdapter
    from vsw.orchestrator import run_observation

    monkeypatch.setattr(PassiveHttpAdapter, "execute", lambda *args: [])
    monkeypatch.setattr(BrowserAdapter, "validate_config", lambda *args: None)
    monkeypatch.setattr(BrowserAdapter, "execute", lambda *args: [])
    for browser, expected in [(False, ["passive-http"]), (True, ["passive-http", "browser"])]:
        report = run_observation(
            manifest(),
            lab_server + "/clean/",
            root=tmp_path,
            use_browser=browser,
            validation_checks=None,
        )
        assert [item["adapter"] for item in report["adapters"]] == expected
        assert report["stage"] == "M1"


@pytest.mark.parametrize("problem", ["budget", "cancel", "truncation"])
def test_mock_pipeline_incomplete(tmp_path, manifest, lab_server, monkeypatch, problem):
    from vsw.orchestrator import run_observation

    def respond(request):
        body = request.url.params.get("q", "")
        if problem == "truncation":
            body += "x" * MAX_BODY_BYTES
        return httpx.Response(200, headers={"content-type": "text/html"}, text=body)

    calls = stub_http(monkeypatch, respond)
    if problem == "cancel":
        original = ValidationAdapter._stream

        def cancel_after_read(self, url, target):
            result = original(self, url, target)
            self.cancel()
            return result

        monkeypatch.setattr(ValidationAdapter, "_stream", cancel_after_read)
    report = run_observation(
        manifest(max_requests=1),
        lab_server + "/vuln/echo",
        root=tmp_path,
        validation_checks=["html-injection", "open-redirect"],
    )
    assert report["status"] != "pass"
    assert report["coverage"]["stop_reason"]
    assert len(calls) == report["coverage"]["requests_made"] == 1
    assert report["evidence_integrity"] == []
    if problem != "budget":
        assert report["findings"] == []
    if problem == "truncation":
        assert report["coverage"]["truncated_pages"]


@pytest.mark.parametrize("case", ["unknown", "profile", "target", "partial"])
def test_cli_blocked_or_incomplete(tmp_path, manifest, lab_server, monkeypatch, case):
    import json

    from typer.testing import CliRunner

    from vsw import cli, orchestrator

    monkeypatch.setattr(orchestrator, "repo_root", lambda: tmp_path)
    stub_http(monkeypatch, lambda request: httpx.Response(200, text="control"))
    path = manifest(profile="observe" if case == "profile" else "lab", max_requests=1)
    args = [
        "validate",
        "--manifest",
        str(path),
        "--target",
        lab_server + ("/outside" if case == "target" else "/vuln/echo"),
        "--check",
        "unknown" if case == "unknown" else "html-injection",
    ]
    if case == "partial":
        args += ["--check", "open-redirect"]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 1, result.output
    output = json.loads(result.output)
    if case == "partial":
        assert output["status"] == "partial"
        assert output["coverage"]["requests_made"] == 1
    else:
        assert output["decision"] == "blocked" and output["reason"]


@pytest.fixture
def offline_manifest(tmp_path):
    """Approved test-only manifest; no socket fixture or target connection."""
    from pathlib import Path

    import yaml

    source = Path(__file__).resolve().parents[1] / "configs/engagements/lab-local.yaml"
    raw = yaml.safe_load(source.read_text())
    raw["expires_at"] = "2099-01-01T00:00:00Z"
    raw["max_rps"] = 1000.0
    raw["origins"] = ["http://127.0.0.1:8787"]
    path = tmp_path / "offline.yaml"
    path.write_text(yaml.safe_dump(raw))
    from vsw.scope import approve_manifest

    approve_manifest(path, "test-only")
    return path


@pytest.mark.parametrize(
    "body",
    [
        "<frameset>{probe}</frameset>",
        "<frameset></frameset>{probe}",
        "{probe}<frameset></frameset>",
        "<script><!--<script></script>{probe}</script>",
        "<script>ordinary()</script>{probe}",
        "{probe}<script>ordinary()</script>",
        "<FRAMESET/>{probe}",
        "{probe}<SCRIPT/>",
    ],
)
def test_offline_unsupported_html_never_validates(tmp_path, offline_manifest, monkeypatch, body):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
    )
    calls = stub_http(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=body.format(probe=request.url.params["q"]),
        ),
    )
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/echo"]))
    assert len(records) == len(calls) == 1
    assert records[0].notes["complete"] and not a.store.verify()
    assert not a.normalize(records)


@pytest.mark.parametrize(
    "body,positive",
    [
        ("<html><body>{probe}</body></html>", True),
        ("<template>{probe}</template>", False),
        ("<textarea>{probe}</textarea>", False),
        ("<style>{probe}</style>", False),
        ("<!--<script><frameset>-->{probe}", True),
        ("<textarea><script><frameset></textarea>{probe}", True),
        ("<style><script><frameset></style>{probe}", True),
        ("&lt;script&gt;&lt;frameset&gt;{probe}", True),
    ],
)
def test_offline_supported_html_contexts(tmp_path, offline_manifest, monkeypatch, body, positive):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
    )
    stub_http(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=body.format(probe=request.url.params["q"]),
        ),
    )
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/echo"]))
    assert len(records) == 1
    assert len(a.normalize(records)) == int(positive)


def test_offline_redirect_with_unsupported_html_still_validates(
    tmp_path, offline_manifest, monkeypatch
):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["open-redirect"]
    )
    stub_http(
        monkeypatch,
        lambda request: httpx.Response(
            302,
            headers={"location": request.url.params["to"], "content-type": "text/html"},
            text="<script><!--<script></script></script><frameset></frameset>",
        ),
    )
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/open-redirect"]))
    assert len(a.normalize(records)) == 1


@pytest.mark.parametrize(
    "target",
    [
        "/vuln/foo/../echo",
        "/vuln/./echo",
        "/vuln/echo?q=unescaped space",
        "/vuln/caf\u00e9",
        "/vuln/echo?q=caf\u00e9",
        "/vuln/echo?q=tab\there",
    ],
)
def test_offline_target_normalization_denied_before_io(
    tmp_path, offline_manifest, monkeypatch, target
):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
    )
    monkeypatch.setattr(httpx, "stream", lambda *args, **kwargs: pytest.fail("unexpected I/O"))
    with pytest.raises(ScopeDenied, match="unchanged ASCII request path/query"):
        a.plan(["http://127.0.0.1:8787" + target])
    assert a.guard.requests == 0 and not a.store.exchanges()


def test_offline_generated_probe_normalization_denied_before_io(
    tmp_path, offline_manifest, monkeypatch
):
    from vsw.adapters import validation

    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
    )
    monkeypatch.setattr(validation, "urlencode", lambda query: "q=unescaped space")
    monkeypatch.setattr(httpx, "stream", lambda *args, **kwargs: pytest.fail("unexpected I/O"))
    with pytest.raises(ScopeDenied, match="unchanged ASCII request path/query"):
        a.plan(["http://127.0.0.1:8787/vuln/echo"])
    assert a.guard.requests == 0 and not a.store.exchanges()


@pytest.mark.parametrize("protocol", ["HTTP/1.0", "HTTP/2"])
def test_offline_capture_matches_transport_request_and_response(
    tmp_path, offline_manifest, monkeypatch, protocol
):
    engagement = load_engagement(offline_manifest)
    engagement.origins = ["http://localhost:8787"]
    engagement.approval.approved_manifest_sha256 = manifest_hash(engagement)
    guard = ScopeGuard(engagement)
    guard._address_cache["localhost"] = ["127.0.0.1"]
    a = ValidationAdapter(guard, EvidenceStore(tmp_path / "run"), engagement, ["html-injection"])
    observed = []

    def respond(request):
        assert request.method == "GET" and request.url.host == "127.0.0.1"
        assert request.headers["host"] == "localhost:8787"
        response = httpx.Response(
            200,
            headers=[
                (b"Content-Type", b"text/html"),
                (b"X-Reply", b"one"),
                (b"X-Reply", b"two"),
            ],
            extensions={"http_version": protocol.encode(), "reason_phrase": b"Fixture response"},
            text=request.url.params["q"],
        )
        observed.append((request, response))
        return response

    stub_http(monkeypatch, respond)
    records = a.execute(a.plan(["http://localhost:8787/vuln/echo?keep=a%26b&utf8=caf%C3%A9"]))
    (record,) = records
    ((request, response),) = observed
    head = record.request_text.split("\n\n", 1)[0].splitlines()
    assert head[0] == f"{request.method} {request.url.raw_path.decode('ascii')} HTTP/1.1"
    assert head[1:] == [
        f"{k.decode('ascii')}: {v.decode('latin-1')}" for k, v in request.headers.raw
    ]
    assert record.request_headers == dict(request.headers.items())
    assert "connection" in record.request_headers  # HTTPX default omitted by the old capture.
    parts = urlsplit(record.url)
    assert parts.netloc == "localhost:8787"
    assert (parts.path + "?" + parts.query).encode() == request.url.raw_path
    response_head = record.response_text.split("\n\n", 1)[0].splitlines()
    assert response_head[0] == f"{protocol} {response.status_code} {response.reason_phrase}"
    assert response_head[1:] == [
        f"{k.decode('ascii')}: {v.decode('latin-1')}" for k, v in response.headers.raw
    ]
    assert record.notes["request_http_version"] == "HTTP/1.1"
    assert record.notes["http_version"] == protocol
    (finding,) = a.normalize(records)
    assert verify_reproduction(
        finding.reproduction_detail, {r["id"]: r for r in a.store.exchanges()}
    ).verified
    assert not a.store.verify()


def test_real_http10_response_preserves_http11_request(tmp_path, offline_manifest):
    import yaml

    from vsw.scope import approve_manifest

    observed = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):
            observed.append(
                (self.requestline, self.request_version, self.path, list(self.headers.raw_items()))
            )
            body = parse_qs(urlsplit(self.path).query)["q"][0].encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        raw = yaml.safe_load(offline_manifest.read_text())
        raw["origins"] = [origin]
        offline_manifest.write_text(yaml.safe_dump(raw))
        approve_manifest(offline_manifest, "test-only")
        engagement = load_engagement(offline_manifest)
        a = ValidationAdapter(
            ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
        )
        records = a.execute(a.plan([origin + "/vuln/echo?keep=a%26b&utf8=caf%C3%A9"]))
        (record,) = records
        ((request_line, request_version, request_target, request_headers),) = observed
        request_head = record.request_text.split("\n\n", 1)[0].splitlines()
        assert request_version == record.notes["request_http_version"] == "HTTP/1.1"
        assert request_head[0] == request_line == f"GET {request_target} {request_version}"
        # httpcore hoists Host on the wire; HTTPX metadata preserves header tuple order.
        assert sorted(request_head[1:]) == sorted(f"{k}: {v}" for k, v in request_headers)
        assert record.response_text.splitlines()[0] == "HTTP/1.0 200 OK"
        assert record.notes["http_version"] == "HTTP/1.0"
        (finding,) = a.normalize(records)
        assert verify_reproduction(
            finding.reproduction_detail, {r["id"]: r for r in a.store.exchanges()}
        ).verified
        assert a.guard.requests == 1 and not a.store.verify()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("status", [408, 429, 500, 503])
def test_offline_unhealthy_report_stops(tmp_path, offline_manifest, monkeypatch, status):
    from vsw.orchestrator import run_observation

    calls = stub_http(
        monkeypatch,
        lambda request: httpx.Response(
            status, text="unhealthy", headers={"content-type": "text/html"}
        ),
    )
    report = run_observation(
        offline_manifest,
        "http://127.0.0.1:8787/vuln/echo",
        root=tmp_path,
        validation_checks=["html-injection", "open-redirect"],
    )
    assert len(calls) == report["coverage"]["requests_made"] == 1
    assert report["status"] != "pass" and not report["findings"]
    assert report["coverage"]["stop_reason"] == f"target unhealthy: HTTP {status}"
    assert report["adapters"][0]["status"] == "partial"
    assert f"HTTP {status}" in report["adapters"][0]["note"]
    capture = next(item for item in report["evidence"] if item["kind"] == "http")
    assert capture["notes"]["complete"] is False
    assert report["evidence_integrity"] == []


@pytest.mark.parametrize("check", ["html-injection", "open-redirect"])
def test_offline_finding_metadata(tmp_path, offline_manifest, monkeypatch, check):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, [check]
    )

    def respond(request):
        if check == "html-injection":
            return httpx.Response(
                200, headers={"content-type": "text/html"}, text=request.url.params["q"]
            )
        return httpx.Response(302, headers={"location": request.url.params["to"]})

    stub_http(monkeypatch, respond)
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/echo"]))
    (finding,) = a.normalize(records)
    (exchange,) = a.store.exchanges()
    assert finding.first_seen == finding.last_seen == exchange["captured_at"] != ""
    recipe = " ".join(finding.regression_recipe)
    assert check in recipe and ("q set" if check == "html-injection" else "to=") in recipe


@pytest.mark.parametrize("stop", ["cancel", "expiry", "wall", "approval", "rehash"])
def test_offline_trickled_stream_stops_between_chunks(
    tmp_path, offline_manifest, monkeypatch, stop
):
    from datetime import datetime, timedelta

    from vsw.adapters import validation

    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement),
        EvidenceStore(tmp_path / "run"),
        engagement,
        ["html-injection", "open-redirect"],
    )
    consumed = []
    closed = []

    class Trickled(httpx.SyncByteStream):
        def __iter__(self):
            # Accept a marker first, then simulate time/policy changing while
            # waiting for an empty raw chunk (which yields no decoded output).
            marker = next(iter(a._probes.values()))[1]
            consumed.append(f"<{marker}></{marker}>".encode())
            yield consumed[-1]
            if stop == "cancel":
                a.cancel()
            elif stop == "expiry":

                class ExpiredClock(datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return datetime.fromisoformat(engagement.expires_at) + timedelta(seconds=1)

                monkeypatch.setattr(validation, "datetime", ExpiredClock)
            elif stop == "wall":
                a.guard.started -= engagement.max_wall_seconds
            elif stop == "approval":
                engagement.approval.approved = False
            else:
                engagement.max_requests += 1
                engagement.approval.approved_manifest_sha256 = manifest_hash(engagement)
            consumed.append(b"")
            yield consumed[-1]
            pytest.fail("read another raw chunk after the stop")

        def close(self):
            closed.append(True)

    calls = stub_http(
        monkeypatch,
        lambda request: httpx.Response(
            200, headers={"content-type": "text/html"}, stream=Trickled()
        ),
    )
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/echo"]))
    assert len(consumed) == 2 and consumed[0].startswith(b"<vsw-check-")
    assert consumed[1] == b"" and closed
    assert len(calls) == a.guard.requests == 1
    assert not records and not a.normalize(records)
    assert a.failures and a.guard.stop_reason
    assert a.store.verify() == []


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "unknown", "gzip, identity"])
def test_offline_compressed_validation_rejected_before_read(
    tmp_path, offline_manifest, monkeypatch, encoding
):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement),
        EvidenceStore(tmp_path / "run"),
        engagement,
        ["html-injection", "open-redirect"],
    )

    class Unread(httpx.SyncByteStream):
        def __iter__(self):
            pytest.fail("compressed response body must not be consumed or decoded")
            yield b""

    def respond(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, headers={"content-encoding": encoding}, stream=Unread())

    calls = stub_http(monkeypatch, respond)
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/echo"]))
    assert len(calls) == a.guard.requests == 1 and not records
    assert not a.normalize(records)
    assert a.failures and "uncompressed" in a.guard.stop_reason


@pytest.mark.parametrize(
    "content_type,prefix,suffix,reason",
    [
        ("text/html; charset=utf-16le", b"", b"", "unsupported charset"),
        ("text/html; charset=utf-32", b"", b"", "unsupported charset"),
        ("text/html; charset=utf-8", b"\xff\xfe", b"", "BOM"),
        ("text/html; charset=utf-8", b"\xfe\xff", b"", "BOM"),
        ("text/html; charset=utf-8", b"\xff\xfe\x00\x00", b"", "BOM"),
        ("text/html; charset=utf-8", b"\x00\x00\xfe\xff", b"", "BOM"),
        ("text/html; charset=utf-8", b"", b"\xff", "invalid utf-8"),
        ("text/html; charset=utf-8", b"\xef\xbb\xbf", b"\xc0\xaf", "invalid utf-8"),
        ("text/html", b"\xef\xbb\xbf", b"\xff", "invalid utf-8"),
        ("text/html", b"", b"\xc3\xa9", "invalid ascii"),
        ("text/html; charset=ascii", b"", b"\xc3\xa9", "invalid ascii"),
        ("text/html; charset=us-ascii", b"", b"\xc3\xa9", "invalid ascii"),
        ("text/html; charset=ascii", b"\xef\xbb\xbf", b"", "conflicts"),
        ("text/html; charset=utf-8; charset=utf-16le", b"", b"", "duplicate charset"),
        ("text/html; charset=utf-8; CHARSET=utf-8", b"", b"", "duplicate charset"),
        ("text/html; charset=unknown", b"", b"", "unsupported charset"),
        ('text/html; charset=""', b"", b"", "empty charset"),
        ('text/html; charset="utf-8', b"", b"", "ambiguous"),
        ("text/html", b"\x1b$B", b"", "stateful"),
        ("text/html", b"~{", b"", "stateful"),
        ("text/html", b"+/v8-", b"", "stateful"),
        ("text/html", b"\x00", b"", "NUL"),
        ("text/html", b"\x0e", b"", "stateful"),
        ("text/html", b"<meta charset=utf-16le>", b"", "declarations"),
        ("text/html; charset=utf-8", b"<META CHARSET='windows-1252'>", b"", "declarations"),
        ("text/html; charset=utf-8", b"<meta charset=utf-8>", b"", "declarations"),
        (
            "text/html",
            b'<meta http-equiv="content-type" content="text/html; charset=iso-2022-jp">',
            b"",
            "declarations",
        ),
        (
            "text/html; charset=utf-8",
            b'<meta http-equiv="content&#45;type" content="text/html; char&#115;et=utf-16le">',
            b"",
            "declarations",
        ),
        ("text/html", b"<!-- charset=utf-16 -->", b"", "declarations"),
    ],
)
def test_offline_unsupported_encoding_report(
    tmp_path, offline_manifest, monkeypatch, content_type, prefix, suffix, reason
):
    import hashlib

    from vsw.orchestrator import run_observation

    bodies = []

    def respond(request):
        body = prefix + request.url.params["q"].encode("ascii") + suffix
        bodies.append(body)
        if content_type == "text/html; charset=utf-16le" and not prefix:
            body += b" " * (len(body) % 2)
            bodies[-1] = body
            assert "<" not in body.decode("utf-16le")
        return httpx.Response(200, headers={"content-type": content_type}, content=body)

    calls = stub_http(monkeypatch, respond)
    report = run_observation(
        offline_manifest,
        "http://127.0.0.1:8787/vuln/echo",
        root=tmp_path,
        validation_checks=["html-injection", "open-redirect"],
    )
    assert len(calls) == report["coverage"]["requests_made"] == 1
    assert report["status"] == "partial" and not report["findings"]
    assert report["adapters"][0]["status"] == "partial"
    assert "unsupported HTML encoding" in report["coverage"]["stop_reason"]
    assert reason in report["adapters"][0]["note"]
    assert report["coverage"]["entries"][0]["outcome"] == "needs_follow_up"
    capture = next(item for item in report["evidence"] if item["kind"] == "http")
    assert capture["notes"]["complete"] is False
    assert capture["notes"]["html_encoding_supported"] is False
    assert capture["body_sha256"] == hashlib.sha256(bodies[0]).hexdigest()
    assert capture["response_headers"]["content-type"] == content_type
    assert not report["evidence_integrity"]


@pytest.mark.parametrize(
    "headers,prefix,suffix",
    [
        ({"content-type": "text/html"}, b"", b""),
        ({"content-type": "text/html; charset=ascii"}, b"", b""),
        ({"content-type": "text/html; charset=US-ASCII"}, b"", b""),
        ({"content-type": "text/html; charset=UTF-8"}, b"", b"\xc3\xa9"),
        ({"content-type": 'text/html; CHARSET="UtF-8"'}, b"", b"\xc3\xa9"),
        ({"content-type": "text/html; charset=utf8"}, b"", b""),
        ({"content-type": "text/html; charset=utf-8"}, b"\xef\xbb\xbf", b"\xc3\xa9"),
        ({"content-type": "text/html"}, b"\xef\xbb\xbf", b"\xc3\xa9"),
        ({}, b"", b""),
    ],
)
@pytest.mark.parametrize("escaped", [False, True])
def test_offline_supported_encoding_controls(
    tmp_path, offline_manifest, monkeypatch, headers, prefix, suffix, escaped
):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
    )

    def respond(request):
        probe = request.url.params["q"]
        body = prefix + (escape(probe) if escaped else probe).encode() + suffix
        return httpx.Response(200, headers=headers, content=body)

    stub_http(monkeypatch, respond)
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/echo"]))
    assert records[0].notes["complete"] and records[0].notes["html_encoding_supported"]
    assert len(a.normalize(records)) == int(not escaped and bool(headers))
    assert not a.failures and not a.store.verify()
    original = records[0]
    for changed in [
        replace(original, body="<fake></fake>"),
        replace(original, response_headers={"content-type": "text/html; charset=utf-16le"}),
        replace(original, notes={**original.notes, "html_encoding": "forged"}),
    ]:
        assert not a.normalize([changed])


@pytest.mark.parametrize("path,positive", [("/vuln/echo", True), ("/clean/echo", False)])
def test_offline_real_fastapi_utf8(tmp_path, offline_manifest, monkeypatch, path, positive):
    import asyncio

    from vsw.lab import create_app

    app = create_app()

    async def dispatch(request):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
            return await client.get(str(request.url))

    def respond(request):
        response = asyncio.run(dispatch(request))
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        return httpx.Response(
            response.status_code, headers=response.headers, content=response.content
        )

    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
    )
    stub_http(monkeypatch, respond)
    records = a.execute(a.plan(["http://127.0.0.1:8787" + path]))
    assert len(a.normalize(records)) == int(positive)
    assert records[0].notes["html_encoding"] == "utf-8" and not a.failures


@pytest.mark.parametrize("content_type", ["text/html; charset=utf-16le", "text/html; charset=bad"])
def test_offline_redirect_encoding_independent(
    tmp_path, offline_manifest, monkeypatch, content_type
):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["open-redirect"]
    )
    stub_http(
        monkeypatch,
        lambda request: httpx.Response(
            302,
            headers={"location": request.url.params["to"], "content-type": content_type},
            content=b"\xff\xfe<meta charset=bad>\xff",
        ),
    )
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/open-redirect"]))
    assert len(a.normalize(records)) == 1 and not a.failures
    assert records[0].notes["complete"] and records[0].notes["html_encoding"] == "not applicable"


def test_offline_duplicate_content_type_rejected(tmp_path, offline_manifest, monkeypatch):
    engagement = load_engagement(offline_manifest)
    a = ValidationAdapter(
        ScopeGuard(engagement), EvidenceStore(tmp_path / "run"), engagement, ["html-injection"]
    )
    stub_http(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            headers=[("content-type", "text/html; charset=utf-8"), ("Content-Type", "text/html")],
            content=request.url.params["q"].encode(),
        ),
    )
    records = a.execute(a.plan(["http://127.0.0.1:8787/vuln/echo"]))
    assert not records[0].notes["complete"] and not a.normalize(records)
    records[0].notes.update(complete=True, html_encoding_supported=True, html_encoding="utf-8")
    assert not a.normalize(records)
    assert "duplicate Content-Type" in a.failures[0]
