from pathlib import Path

import pytest

from vsw.domain import Coverage, Finding, FindingState, Severity
from vsw.reporting import _safe, render_markdown, write_report


def finding(**overrides) -> Finding:
    data = {
        "id": "F-001",
        "title": "Reflected parameter",
        "asset": "http://127.0.0.1:8787",
        "endpoint": "/vuln/echo",
        "check_id": "reflection.q",
        "check_version": "1",
        "severity": Severity.MEDIUM,
        "confidence": "high",
        "state": FindingState.VALIDATED,
        "evidence_ids": ["E-001"],
        "detail": "payload <script>alert(1)</script> | pipe",
        "reproduction": ["GET /vuln/echo?q=x"],
        "impact": "unproven",
        "remediation": "encode",
    }
    data.update(overrides)
    return Finding(**data)


def render(findings: list[Finding], skipped: list[dict[str, str]] | None = None) -> str:
    return render_markdown(
        run_id="obs-test",
        engagement={
            "id": "unit",
            "profile": "lab",
            "owner": "tester",
            "approver": "tester",
            "authorization_ref": "unit",
            "expires_at": "2030-01-01T00:00:00Z",
            "origins": ["http://127.0.0.1:8787"],
            "methods": ["GET"],
            "path_prefixes": ["/vuln"],
            "mutation_allowed": False,
            "manifest_sha256": "a" * 64,
        },
        findings=findings,
        coverage=Coverage(
            targets_planned=["http://127.0.0.1:8787/vuln/"],
            targets_visited=["http://127.0.0.1:8787/vuln/"],
            requests_made=2,
            request_limit=10,
            skipped=skipped or [],
            stop_reason="",
        ),
        evidence=[
            {
                "id": "E-001",
                "kind": "http",
                "status": 200,
                "url": "http://127.0.0.1:8787/vuln/echo?q=x",
                "body_sha256": "b" * 64,
                "truncated": False,
            }
        ],
        adapters=[
            {"adapter": "passive-http", "status": "completed", "requests": 1, "duration_s": 0.5}
        ],
        budget={"calls": 0, "spent_usd": 0.0, "elapsed_seconds": 1.0, "limits": {}},
        started="2026-11-12T00:00:00Z",
        finished="2026-11-12T00:00:01Z",
    )


def test_target_content_is_html_escaped():
    markdown = render([finding(title="Reflected | parameter")])
    assert "<script>alert(1)</script>" not in markdown
    assert "<script>" not in markdown
    assert "\\<script\\>" in markdown
    assert "Reflected \\| parameter" in markdown


def test_target_text_cannot_form_markdown_links_or_code():
    markdown = render([finding(title="[click](https://evil.invalid) `code`")])
    assert "[click](" not in markdown
    assert "\\[click\\]" in markdown
    assert "\\`code\\`" in markdown


def test_report_states_coverage_and_limits():
    markdown = render(
        [], skipped=[{"url": "https://cdn.example.invalid/x.js", "reason": "not approved"}]
    )
    assert "## Untested areas and limits" in markdown
    assert "No findings were produced" in markdown
    assert "cdn.example.invalid" in markdown
    assert "blocked by scope enforcement" in markdown


def test_report_shows_validated_count():
    markdown = render([finding()])
    assert "Validated findings: **1**" in markdown
    assert "F-001" in markdown
    assert "E-001" in markdown


def test_write_report_refuses_path_traversal(tmp_path: Path):
    with pytest.raises(ValueError, match="outside the run directory"):
        _safe(tmp_path, "../escape.md")
    assert not (tmp_path.parent / "escape.md").exists()


def test_write_report_stays_inside_the_run(tmp_path: Path):
    md, payload = write_report(tmp_path, payload={"findings": []}, markdown="# hi\n")
    assert md == tmp_path.resolve() / "report.md"
    assert payload.exists()
    assert (tmp_path / "report.md").read_text() == "# hi\n"
