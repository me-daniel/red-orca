"""Runtime-owned coverage recording.

Agents can construct `CoverageEntry`, whose source is fixed to `agent`.
Only this module constructs `MachineCoverageEntry`, so a model or adapter cannot
label its own claim as machine-observed. The ledger also checks that every cited
evidence id exists in the run's verified evidence store.
"""

from __future__ import annotations

from typing import Any, Literal

from .domain import CoverageEntry, CoverageOutcome, CoverageRecord, Finding
from .evidence import EvidenceStore
from .util import utc_now


class MachineCoverageEntry(CoverageRecord):
    """Coverage the runtime observed, not an agent claim."""

    source: Literal["machine"] = "machine"


class CoverageLedger:
    def __init__(self, store: EvidenceStore) -> None:
        self.store = store
        self.entries: list[CoverageRecord] = []
        self._verified: bool | None = None

    def _evidence_verified(self) -> bool:
        """Verify the store once; a ledger is built over finalized evidence."""
        if self._verified is None:
            self._verified = not self.store.verify()
        return self._verified

    def _validate(self, evidence_ids: list[str], outcome: CoverageOutcome) -> None:
        if outcome == CoverageOutcome.NO_ISSUE_FOUND and not evidence_ids:
            raise ValueError("no_issue_found coverage requires evidence_ids")
        if evidence_ids and not self._evidence_verified():
            raise ValueError("coverage references unverified run evidence")
        missing = [evidence_id for evidence_id in evidence_ids if not self.store.has(evidence_id)]
        if missing:
            raise ValueError(f"coverage references missing evidence: {', '.join(missing)}")

    def record(self, entry: CoverageEntry) -> CoverageEntry:
        self._validate(entry.evidence_ids, entry.outcome)
        if not entry.recorded_at:
            entry = entry.model_copy(update={"recorded_at": utc_now()})
        self.entries.append(entry)
        return entry

    def record_observation(
        self,
        *,
        target: str,
        adapters: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        findings: list[Finding],
        stop_reason: str = "",
    ) -> None:
        """Turn adapter results into machine coverage; incomplete work stays open."""
        finding_ids = {item for finding in findings for item in finding.evidence_ids}
        for adapter in adapters:
            name = str(adapter["adapter"])
            evidence_ids = [
                str(item["id"])
                for item in evidence
                if item.get("source") == name
                and item.get("kind") in {"http", "browser"}
                and item.get("id")
            ]
            # Capabilities are advertised, not proof that every check ran.
            risk_area = "adapter observation"
            status = str(adapter["status"])
            if status != "completed" or stop_reason:
                outcome = CoverageOutcome.NEEDS_FOLLOW_UP
                note = str(adapter.get("note") or stop_reason or "adapter did not complete")
            elif any(item in finding_ids for item in evidence_ids):
                outcome = CoverageOutcome.REPORTED
                note = "finding(s) linked to this adapter's captures"
            elif evidence_ids:
                outcome = CoverageOutcome.NEEDS_FOLLOW_UP
                note = "captures recorded; per-check negative coverage was not measured"
            else:
                outcome = CoverageOutcome.NEEDS_FOLLOW_UP
                note = "adapter completed without captured evidence"
            self.record_machine(
                surface=target,
                risk_area=risk_area,
                outcome=outcome,
                evidence_ids=evidence_ids,
                evidence=note,
                agent=name,
            )

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
