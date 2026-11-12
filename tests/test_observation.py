from pathlib import Path

import pytest

from vsw.evidence import EvidenceStore
from vsw.orchestrator import run_observation
from vsw.scope import ScopeDenied


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
