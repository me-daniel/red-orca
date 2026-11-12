import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from vsw.evidence import EvidenceStore
from vsw.orchestrator import run_observation
from vsw.scope import ScopeDenied, approve_manifest


@pytest.mark.parametrize("tamper", [False, True])
def test_run_artifacts_from_mock_capture_without_sockets(tmp_path, monkeypatch, tamper):
    """Exercise orchestration and real analysis with a deterministic local capture mock."""
    from vsw.adapters.passive_http import PassiveHttpAdapter

    manifest_path = tmp_path / "engagement.yaml"
    manifest_path.write_text(
        json.dumps(
            {
                "id": "mock-fixture",
                "owner": "tester",
                "approver": "tester",
                "authorization_ref": "secret=authsecret",
                "expires_at": "2030-01-01T00:00:00Z",
                "origins": ["http://127.0.0.1:8787"],
                "path_prefixes": ["/vuln"],
            }
        )
    )
    approve_manifest(manifest_path, "tester")

    def capture(self, plan):
        url = plan.destinations[0]
        self.guard.authorize(url, "GET")
        parts = urlsplit(url)
        request = f"GET {parts.path}?{parts.query} HTTP/1.1\nHost: 127.0.0.1:8787\n\n"
        body = "<html><b>vsw-marker-mock</b></html>"
        record = self.store.capture(
            kind="http",
            url=url,
            status=200,
            response_headers={"Content-Type": "text/html"},
            body=body,
            request_text=request,
            response_text=f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{body}",
            source=self.name,
            notes={"content_type": "text/html"},
        )
        if tamper:
            path = self.store.dir / f"{record.id}.json"
            path.write_text(path.read_text().replace("vsw-marker-mock", "forged-marker"))
        return [record]

    monkeypatch.setattr(PassiveHttpAdapter, "execute", capture)
    target = (
        "http://127.0.0.1:8787/vuln/echo?"
        "q=%3Cb%3Evsw-marker-mock%3C%2Fb%3E&token=topsecret"
    )
    report = run_observation(manifest_path, target, use_browser=False, root=tmp_path)
    run_dir = Path(report["run_dir"])
    assert {item["check_id"] for item in report["findings"]} >= {"reflection.q"}
    assert json.loads((run_dir / "findings.json").read_text()) == {
        key: value for key, value in report.items() if key != "run_dir"
    }
    assert json.loads((run_dir / "coverage.json").read_text()) == report["coverage"]
    run_summary = json.loads((run_dir / "run.json").read_text())
    assert run_summary["status"] == report["status"]
    assert run_summary["findings"] == len(report["findings"])
    for name in ("report.md", "findings.json", "coverage.json", "exchanges.json", "run.json"):
        contents = (run_dir / name).read_text()
        assert "topsecret" not in contents
        assert "authsecret" not in contents
    if tamper:
        assert report["status"] == "fail"
        assert report["evidence"] == []
        assert all(item["state"] == "inconclusive" for item in report["findings"])
        assert all(not item["reproduction_verified"] for item in report["findings"])
        assert json.loads((run_dir / "exchanges.json").read_text())["exchanges"] == []
        assert run_summary["validated"] == 0
        assert all(
            entry["outcome"] == "needs_follow_up" and not entry["evidence_ids"]
            for entry in report["coverage"]["entries"]
        )
    else:
        assert report["status"] == "pass"
        assert report["evidence_integrity"] == []
        assert next(item for item in report["findings"] if item["check_id"] == "reflection.q")[
            "reproduction_verified"
        ] is True
        exchange = json.loads((run_dir / "exchanges.json").read_text())["exchanges"][0]
        assert exchange["exchange_id"] == exchange["evidence_id"] == report["evidence"][0]["id"]
        assert exchange["record_sha256"] == report["evidence"][0]["record_sha256"]
        assert "request_text" not in exchange
        assert run_summary["validated"] == sum(
            item["state"] == "validated" for item in report["findings"]
        )


def test_vulnerable_reflection_is_validated_with_evidence(tmp_path, manifest, lab_server):
    path = manifest()
    report = run_observation(
        path,
        f"{lab_server}/vuln/echo?q=%3Cb%3Evsw-marker-1%3C%2Fb%3E",
        use_browser=False,
        root=tmp_path,
    )
    validated = [item for item in report["findings"] if item["state"] == "validated"]
    assert [item["check_id"] for item in validated] == ["reflection.q"]
    assert "<b>" in (Path(report["run_dir"]) / "findings.json").read_text(encoding="utf-8")
    assert report["evidence_integrity"] == []
    assert report["status"] == "pass"

    run_dir = Path(report["run_dir"])
    markdown = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Validated findings: **1**" in markdown
    assert "## Untested areas and limits" in markdown
    assert EvidenceStore(run_dir).verify() == []
    exported = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    assert exported["findings"] == report["findings"]
    assert json.loads((run_dir / "coverage.json").read_text()) == report["coverage"]
    run = json.loads((run_dir / "run.json").read_text())
    assert (run["status"], run["findings"], run["validated"]) == (
        report["status"], len(report["findings"]), len(validated)
    )
    exchanges = json.loads((run_dir / "exchanges.json").read_text())["exchanges"]
    evidence_by_id = {item["id"]: item for item in report["evidence"]}
    assert exchanges
    assert {item["exchange_id"] for item in exchanges} == {
        item["id"] for item in report["evidence"] if item["kind"] == "http"
    }
    assert all(item["record_sha256"] == evidence_by_id[item["evidence_id"]]["record_sha256"] for item in exchanges)


def test_clean_control_produces_no_findings(tmp_path, manifest, lab_server):
    path = manifest()
    report = run_observation(path, f"{lab_server}/clean/", use_browser=True, root=tmp_path)
    # Zero findings only means something when observation actually ran.
    assert report["status"] == "pass"
    assert report["evidence"], "clean control captured no evidence"
    assert [item["adapter"] for item in report["adapters"] if item["status"] == "completed"]
    assert report["findings"] == []
    assert report["evidence_integrity"] == []
    markdown = Path(report["run_dir"], "report.md").read_text(encoding="utf-8")
    assert "No findings were produced" in markdown
    assert "Validated findings: **0**" in markdown


def test_browser_blocks_and_records_out_of_scope_subresources(tmp_path, manifest, lab_server):
    path = manifest()
    report = run_observation(
        path, f"{lab_server}/vuln/third-party", use_browser=True, root=tmp_path
    )
    skipped_urls = {item["url"] for item in report["coverage"]["skipped"]}
    assert "https://cdn.example.invalid/vsw-lab.js" in skipped_urls
    check_ids = {item["check_id"] for item in report["findings"]}
    assert "browser.third_party_request" in check_ids
    assert report["evidence_integrity"] == []
    assert all(
        "cdn.example.invalid" in item["url"] or "198.51.100.7" in item["url"]
        for item in report["coverage"]["skipped"]
    )


def test_redirect_to_out_of_scope_origin_is_stopped(tmp_path, manifest, lab_server):
    path = manifest()
    report = run_observation(
        path, f"{lab_server}/vuln/open-redirect", use_browser=False, root=tmp_path
    )
    assert any(item["url"] == "https://example.invalid/" for item in report["coverage"]["skipped"])
    blocked = [item for item in report["evidence"] if item["kind"] == "blocked"]
    assert blocked


def test_out_of_scope_target_is_refused_before_any_request(tmp_path, manifest, lab_server):
    path = manifest(path_prefixes=["/clean"])
    with pytest.raises(ScopeDenied):
        run_observation(path, f"{lab_server}/vuln/", use_browser=False, root=tmp_path)


def test_request_limit_stops_the_crawl(tmp_path, manifest, lab_server):
    path = manifest(max_requests=1)
    report = run_observation(path, f"{lab_server}/vuln/", use_browser=False, root=tmp_path)
    assert report["coverage"]["requests_made"] <= 1
    assert report["coverage"]["stop_reason"] in {"request limit reached", ""}
    if report["coverage"]["stop_reason"]:
        assert report["status"] == "partial"
        assert all(
            entry["outcome"] != "no_issue_found" for entry in report["coverage"]["entries"]
        )


def test_https_target_cannot_pass_as_a_completed_run(tmp_path, manifest):
    path = manifest(origin="https://127.0.0.1:443")
    report = run_observation(path, "https://127.0.0.1:443/vuln/", use_browser=True, root=tmp_path)
    assert report["status"] == "fail"
    adapters = {item["adapter"]: item for item in report["adapters"]}
    assert adapters["passive-http"]["status"] == "failed"
    assert adapters["passive-http"]["note"].startswith("GET https://")
    assert adapters["browser"]["status"] in {"failed", "unavailable"}


def test_missing_browser_reports_partial_coverage(tmp_path, manifest, lab_server, monkeypatch):
    from vsw.adapters.base import AdapterUnavailable
    from vsw.adapters.browser import BrowserAdapter

    def unavailable(self):
        raise AdapterUnavailable("playwright is not installed")

    monkeypatch.setattr(BrowserAdapter, "validate_config", unavailable)
    report = run_observation(
        manifest(), f"{lab_server}/vuln/echo?q=partial-run", use_browser=True, root=tmp_path
    )
    assert report["status"] == "partial"
    adapters = {item["adapter"]: item for item in report["adapters"]}
    assert adapters["passive-http"]["status"] == "completed"
    assert adapters["browser"]["status"] == "unavailable"
    assert any(
        entry["agent"] == "browser" and entry["outcome"] == "needs_follow_up"
        for entry in report["coverage"]["entries"]
    )


def test_passive_http_connects_to_the_checked_address(tmp_path, manifest, lab_server, monkeypatch):
    import socket

    from vsw.adapters.passive_http import PassiveHttpAdapter
    from vsw.scope import ScopeGuard, load_engagement

    port = int(urlsplit(lab_server).port or 80)
    engagement = load_engagement(manifest(origin=f"http://rebind.test:{port}"))
    guard = ScopeGuard(
        engagement,
        resolver=lambda host, _: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))],
    )
    real = socket.getaddrinfo

    def no_rebind(host, *args, **kwargs):
        if host == "rebind.test":
            raise OSError("hostname was resolved again after the scope check")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", no_rebind)
    adapter = PassiveHttpAdapter(guard, EvidenceStore(tmp_path / "evidence"), engagement)
    records = adapter.execute(
        adapter.plan([f"http://rebind.test:{port}/vuln/echo?q=pinned-passive"])
    )
    assert records
    assert records[0].status == 200
    assert records[0].notes["peer"] == "127.0.0.1"


def test_reproduction_is_captured_and_redacted_end_to_end(tmp_path, manifest, lab_server):
    secret = "vsw-topsecret-token"
    target = (
        f"{lab_server}/vuln/echo?q=%3Cb%3Evsw-marker-3%3C%2Fb%3E&token={secret}"
    )
    report = run_observation(manifest(), target, use_browser=False, root=tmp_path)
    assert report["status"] == "pass"
    evidence_ids = {item["id"] for item in report["evidence"]}
    findings = {item["check_id"]: item for item in report["findings"]}
    finding = findings["reflection.q"]
    assert finding["reproduction_verified"] is True
    detail = finding["reproduction_detail"]
    step = detail["steps"][0]
    assert step["exchange_id"] in evidence_ids
    assert step["exchange_id"] == step["evidence_ids"][0]
    assert "GET /vuln/echo" in step["request"]
    assert "HTTP/1.1 200" in step["response"]

    run_dir = Path(report["run_dir"])
    markdown = (run_dir / "report.md").read_text(encoding="utf-8")
    exported = (run_dir / "findings.json").read_text(encoding="utf-8")
    assert "Reproduction (captured):" in markdown
    assert secret not in markdown
    assert secret not in exported
    assert "<redacted>" in markdown
    assert "<redacted>" in exported
    for name in ("coverage.json", "exchanges.json", "run.json"):
        assert secret not in (run_dir / name).read_text(encoding="utf-8")


def test_runtime_records_machine_coverage_with_valid_evidence(tmp_path, manifest, lab_server):
    report = run_observation(manifest(), f"{lab_server}/clean/", use_browser=False, root=tmp_path)
    assert report["status"] == "pass"
    evidence_ids = {item["id"] for item in report["evidence"]}
    machine = [
        entry for entry in report["coverage"]["entries"] if entry["source"] == "machine"
    ]
    assert machine
    clean = [entry for entry in machine if entry["outcome"] == "no_issue_found"]
    assert clean
    for entry in clean:
        assert entry["evidence_ids"]
        assert set(entry["evidence_ids"]) <= evidence_ids

    markdown = Path(report["run_dir"], "report.md").read_text(encoding="utf-8")
    assert "### Coverage ledger" in markdown
    assert "| machine |" in markdown
    assert "| no_issue_found |" in markdown
