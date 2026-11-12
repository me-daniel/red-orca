"""Typed task envelopes and results shared by every adapter."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Phase(str, Enum):
    BUILD = "build"
    ASSESSMENT = "assessment"


class Status(str, Enum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNAVAILABLE = "unavailable"
    NEEDS_OPERATOR = "needs_operator"


class TaskEnvelope(BaseModel):
    """What a delegate is allowed to do. The model never widens this."""

    id: str
    purpose: str
    phase: Phase = Phase.BUILD
    parent_run: str | None = None
    base_commit: str | None = None
    family: str  # claude | codex
    label: str  # opus | sonnet | gpt-6.1-sol
    effort: str  # medium | high
    budget_usd: float = 0.5
    timeout_s: float = 120.0
    permitted_paths: list[str] = Field(default_factory=lambda: ["**"])
    permitted_tools: list[str] = Field(default_factory=lambda: ["text"])
    escalation_reason: str | None = None


class TaskResult(BaseModel):
    id: str
    status: Status
    model_requested: str
    model_actual: str | None = None
    effort_requested: str
    effort_actual: str | None = None
    output: str = ""
    changed_files: list[str] = Field(default_factory=list)
    tests: dict[str, object] = Field(default_factory=dict)
    usage: dict[str, object] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    cost_usd: float = 0.0
    duration_s: float = 0.0
