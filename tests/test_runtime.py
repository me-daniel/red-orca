"""Runtime-owned coverage ledger tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from vsw.domain import CoverageEntry, CoverageOutcome
from vsw.evidence import EvidenceStore
from vsw.runtime import CoverageLedger, MachineCoverageEntry


def _store(tmp_path: Path) -> EvidenceStore:
    store = EvidenceStore(tmp_path)
    store.capture(
        kind="http",
        url="http://127.0.0.1:8787/clean/",
        method="GET",
        status=200,
        body="clean",
        request_text="GET /clean/ HTTP/1.1\nHost: 127.0.0.1:8787\n\n",
        response_text="HTTP/1.1 200 OK\n\nclean",
        source="passive-http",
    )
    return store


def test_no_issue_found_requires_existing_evidence(tmp_path: Path):
    store = _store(tmp_path)
    ledger = CoverageLedger(store)
    entry = CoverageEntry(
        surface="/clean/",
        risk_area="reflection",
        outcome=CoverageOutcome.NO_ISSUE_FOUND,
        evidence_ids=["E-001"],
        evidence="parameterized output",
    )
    recorded = ledger.record(entry)
    assert recorded.source == "agent"
    assert recorded.recorded_at

    with pytest.raises(ValueError, match="missing evidence"):
        ledger.record(
            CoverageEntry(
                surface="/clean/",
                risk_area="reflection",
                outcome=CoverageOutcome.NO_ISSUE_FOUND,
                evidence_ids=["E-999"],
                evidence="claimed clean",
            )
        )


def test_machine_coverage_is_created_only_by_runtime(tmp_path: Path):
    store = _store(tmp_path)
    ledger = CoverageLedger(store)
    entry = ledger.record_machine(
        surface="/clean/",
        risk_area="reflection",
        outcome=CoverageOutcome.NO_ISSUE_FOUND,
        evidence_ids=["E-001"],
        evidence="runtime observed no finding",
    )
    assert isinstance(entry, MachineCoverageEntry)
    assert entry.source == "machine"
    assert entry.evidence_ids == ["E-001"]


def test_tampered_evidence_cannot_support_negative_coverage(tmp_path: Path):
    store = _store(tmp_path)
    record_path = store.dir / "E-001.json"
    record_path.write_text(record_path.read_text().replace("clean", "forged"))
    ledger = CoverageLedger(store)
    with pytest.raises(ValueError, match="unverified run evidence"):
        ledger.record_machine(
            surface="/clean/",
            risk_area="reflection",
            outcome=CoverageOutcome.NO_ISSUE_FOUND,
            evidence_ids=["E-001"],
        )


@pytest.mark.parametrize("status, stop_reason", [("partial", ""), ("completed", "request limit reached")])
def test_incomplete_adapter_never_reports_no_issue_found(
    tmp_path: Path, status: str, stop_reason: str
):
    store = _store(tmp_path)
    ledger = CoverageLedger(store)
    ledger.record_observation(
        target="http://127.0.0.1:8787/clean/",
        adapters=[{"adapter": "passive-http", "status": status}],
        evidence=store.records(),
        findings=[],
        stop_reason=stop_reason,
    )
    assert ledger.entries[0].source == "machine"
    assert ledger.entries[0].outcome == CoverageOutcome.NEEDS_FOLLOW_UP
    assert ledger.entries[0].evidence_ids == ["E-001"]
