"""Spend, call, and wall-clock budget enforcement."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from .config import Limits


class BudgetExceeded(RuntimeError):
    """Raised before starting work that would exceed a configured limit."""


@dataclass
class Budget:
    limits: Limits
    started: float = field(default_factory=time.monotonic)
    calls: int = 0
    spent_usd: float = 0.0
    calls_by_model: dict[str, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def remaining_seconds(self) -> float:
        return self.limits.max_wall_seconds_per_run - self.elapsed()

    def check(self) -> None:
        if self.elapsed() >= self.limits.max_wall_seconds_per_run:
            raise BudgetExceeded(
                f"wall-clock limit reached: {self.elapsed():.1f}s "
                f">= {self.limits.max_wall_seconds_per_run:.1f}s"
            )
        if self.calls >= self.limits.max_delegate_calls_per_run:
            raise BudgetExceeded(
                f"delegate-call limit reached: {self.calls} "
                f">= {self.limits.max_delegate_calls_per_run}"
            )
        if self.spent_usd >= self.limits.max_usd_per_run:
            raise BudgetExceeded(
                f"spend limit reached: ${self.spent_usd:.4f} >= ${self.limits.max_usd_per_run:.2f}"
            )

    def call_timeout(
        self, requested: float | None = None, *, implementation: bool = False
    ) -> float:
        """Advice and review stay short; implementation gets a longer window."""
        cap = (
            self.limits.implementation_timeout_seconds
            if implementation
            else self.limits.per_call_timeout_seconds
        )
        timeout = requested or cap
        timeout = min(timeout, cap)
        remaining = self.remaining_seconds()
        if remaining <= 0:
            raise BudgetExceeded("no wall-clock budget remains")
        return min(timeout, remaining)

    def reset_clock(self) -> None:
        """Start a fresh wall-clock window, keeping cumulative calls and spend.

        The coordinator may sit idle between delegated tasks; idle time must not
        consume a task's wall-clock budget. Calls and spend stay cumulative so
        run-level limits still hold.
        """
        with self._lock:
            self.started = time.monotonic()

    def begin_call(self, model: str) -> None:
        with self._lock:
            self.check()
            self.calls += 1
            self.calls_by_model[model] = self.calls_by_model.get(model, 0) + 1

    def record(self, cost_usd: float = 0.0) -> None:
        with self._lock:
            self.spent_usd += max(0.0, cost_usd)

    def status(self) -> dict[str, object]:
        return {
            "elapsed_seconds": round(self.elapsed(), 3),
            "calls": self.calls,
            "calls_by_model": dict(self.calls_by_model),
            "spent_usd": round(self.spent_usd, 6),
            "limits": self.limits.as_dict(),
        }
