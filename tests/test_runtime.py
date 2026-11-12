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
