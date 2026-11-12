"""Runtime-owned coverage recording.

Agents can construct `CoverageEntry`, whose source is fixed to `agent`.
Only this module constructs `MachineCoverageEntry`, so a model or adapter cannot
label its own claim as machine-observed. The ledger also checks that every cited
evidence id exists in the run's verified evidence store.
"""

from __future__ import annotations

from typing import Literal

from .domain import CoverageEntry, CoverageOutcome, CoverageRecord
from .evidence import EvidenceStore
from .util import utc_now


class MachineCoverageEntry(CoverageRecord):
    """Coverage the runtime observed, not an agent claim."""

    source: Literal["machine"] = "machine"


class CoverageLedger:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store
        self.entries: list[CoverageRecord] = []

    def _validate(self, evidence_ids: list[str], outcome: CoverageOutcome) -> None:
        if outcome == CoverageOutcome.NO_ISSUE_FOUND and not evidence_ids:
            raise ValueError("no_issue_found coverage requires evidence_ids")
        missing = [evidence_id for evidence_id in evidence_ids if not self.store.has(evidence_id)]
        if missing:
            raise ValueError(f"coverage references missing evidence: {', '.join(missing)}")

    def record(self, entry: CoverageEntry) -> CoverageEntry:
        self._validate(entry.evidence_ids, entry.outcome)
        if not entry.recorded_at:
            entry = entry.model_copy(update={"recorded_at": utc_now()})
        self.entries.append(entry)
        return entry

    def record_machine(
        self,
        *,
        surface: str,
        risk_area: str,
        outcome: CoverageOutcome,
        evidence_ids: list[str],
        evidence: str = "",
        agent: str = "runtime",
    ) -> MachineCoverageEntry:
        entry = MachineCoverageEntry(
            surface=surface,
            risk_area=risk_area,
            outcome=outcome,
            evidence=evidence,
            evidence_ids=evidence_ids,
            agent=agent,
            recorded_at=utc_now(),
        )
        self._validate(evidence_ids, outcome)
        self.entries.append(entry)
        return entry
