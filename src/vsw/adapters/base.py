"""Adapter contract shared by every engine, including AntiFox and Strix later."""

from __future__ import annotations

from typing import Protocol

from ..domain import CheckPlan, Finding
from ..evidence import EvidenceRecord


class AdapterError(RuntimeError):
    pass


class AdapterUnavailable(AdapterError):
    """The adapter cannot run here. Reported as `unavailable`, never faked."""


class Adapter(Protocol):
    name: str
    cancelled: bool

    def capabilities(self) -> set[str]: ...

    def validate_config(self) -> None: ...

    def plan(self, seeds: list[str]) -> CheckPlan: ...

    def execute(self, plan: CheckPlan) -> list[EvidenceRecord]: ...

    def cancel(self) -> None: ...

    def normalize(self, records: list[EvidenceRecord]) -> list[Finding]: ...


class BaseAdapter:
    """Cancellation flag and default no-op pieces."""

    name = "base"

    def __init__(self) -> None:
        self.cancelled = False

    def capabilities(self) -> set[str]:
        return set()

    def validate_config(self) -> None:
        return None

    def cancel(self) -> None:
        self.cancelled = True

    def normalize(self, records: list[EvidenceRecord]) -> list[Finding]:
        return []
