"""Reproduction redaction and verified-link tests."""

from __future__ import annotations

import json
from pathlib import Path

from vsw.domain import Finding, FindingState, Reproduction, ReproStep, Severity
from vsw.evidence import EvidenceStore, redact_http_text
from vsw.reporting import write_report
from vsw.reproduction import (
    finding_export,
    redact_reproduction,
    verify_reproduction,
)


def _finding(repro: Reproduction | None) -> Finding:
    return Finding(
        id="F-001",
        title="Captured reflection",
        asset="http://127.0.0.1:8787",
        endpoint="/vuln/echo",
        check_id="reflection.q",
        check_version="1",
        severity=Severity.MEDIUM,
        confidence="high",
        state=FindingState.VALIDATED,
        evidence_ids=["E-001"],
        reproduction_detail=repro,
    )


def _store_with_exchange(tmp_path: Path) -> tuple[EvidenceStore, dict[str, dict]]:
    store = EvidenceStore(tmp_path)
    record = store.capture(
        kind="http",
        url="http://127.0.0.1:8787/vuln/echo?q=x",
        method="GET",
        status=200,
        request_headers={"Host": "127.0.0.1:8787"},
        response_headers={"Content-Type": "text/html"},
        body="pong",
        request_text="GET /vuln/echo?q=x HTTP/1.1\nHost: 127.0.0.1:8787\n\n",
        response_text="HTTP/1.1 200 OK\nContent-Type: text/html\n\npong",
        source="passive-http",
    )
    records = {item["id"]: item for item in store.records()}
    assert record.id in records
    return store, records


def test_redact_http_text_redacts_headers_and_body():
    raw = (
        "GET /login?token=topsecret HTTP/1.1\n"
        "Authorization: Bearer topsecret\n"
        "Cookie: session=topsecret\n"
        "X-Trace: user@example.invalid\n"
        "Set-Cookie: sid=topsecret; HttpOnly\n"
        "\n"
        "password=topsecret&email=user@example.invalid"
    )
    redacted = redact_http_text(raw)
    assert "topsecret" not in redacted
    assert "user@example.invalid" not in redacted
    assert "Authorization: <redacted>" in redacted
    assert "Cookie: <redacted>" in redacted
    assert "sid=<redacted>; HttpOnly" in redacted
    assert "token=<redacted>" in redacted


def test_redact_reproduction_redacts_every_text_field():
    repro = Reproduction(
        entry_point="GET /x?token=topsecret",
        prerequisites=["password=topsecret"],
        provenance="secret=topsecret",
        steps=[
            ReproStep(
                request="GET /x HTTP/1.1\nAuthorization: Bearer topsecret\n\n",
                response="HTTP/1.1 200 OK\nSet-Cookie: sid=topsecret; HttpOnly\n\n",
                expected="token=topsecret",
                proves="secret=topsecret",
                exchange_id="E-001",
                evidence_ids=["E-001"],
            )
        ],
    )
    redacted = redact_reproduction(repro)
    dumped = redacted.model_dump_json()
    assert "topsecret" not in dumped
    assert "<redacted>" in dumped


def test_verified_exchange_links_are_captured(tmp_path: Path):
    _, records = _store_with_exchange(tmp_path)
    repro = Reproduction(
        entry_point="GET /vuln/echo?q=x",
        steps=[
            ReproStep(
                request="GET /vuln/echo?q=x HTTP/1.1\nHost: 127.0.0.1:8787\n\n",
                response="HTTP/1.1 200 OK\nContent-Type: text/html\n\npong",
                expected="200",
                proves="reflection",
                exchange_id="E-001",
                evidence_ids=["E-001"],
            )
        ],
    )
    check = verify_reproduction(repro, records)
    assert check.verified is True, check.errors
    payload = finding_export(_finding(repro), records)
    assert payload["reproduction_verified"] is True


def test_unverified_links_are_not_captured(tmp_path: Path):
    _, records = _store_with_exchange(tmp_path)
    repro = Reproduction(
        entry_point="GET /vuln/echo?q=x",
        steps=[
            ReproStep(
                request="GET /vuln/echo?q=other HTTP/1.1\nHost: 127.0.0.1:8787\n\n",
                response="HTTP/1.1 200 OK\nContent-Type: text/html\n\npong",
                exchange_id="E-001",
                evidence_ids=["E-001"],
            )
        ],
    )
    check = verify_reproduction(repro, records)
    assert check.verified is False
    assert any("target does not match" in error for error in check.errors)
    payload = finding_export(_finding(repro), records)
    assert payload["reproduction_verified"] is False


def test_json_export_redacts_reproduction_even_when_unverified(tmp_path: Path):
    repro = Reproduction(
        entry_point="GET /x?token=topsecret",
        steps=[
            ReproStep(
                request="GET /x HTTP/1.1\nAuthorization: Bearer topsecret\n\n",
                response="HTTP/1.1 200 OK\n\npong",
                exchange_id="E-999",
                evidence_ids=["E-999"],
            )
        ],
    )
    payload = {"findings": [{"reproduction_detail": repro.model_dump(mode="json")}]}
    write_report(tmp_path, payload=payload, markdown="# report\n")
    exported = (tmp_path / "findings.json").read_text(encoding="utf-8")
    assert "topsecret" not in exported
    assert "<redacted>" in exported
    assert json.loads(exported)["findings"][0]["reproduction_detail"]["steps"][0][
        "request"
    ].startswith("GET /x")
