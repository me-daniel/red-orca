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


class Role(str, Enum):
    """What a delegate is allowed to do. Enforced by the gateway, not prompts."""

    ADVICE = "advice"
    IMPLEMENT = "implement"
    REVIEW = "review"


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
    role: Role = Role.IMPLEMENT
    budget_usd: float = 0.5
    timeout_s: float = 120.0
    permitted_paths: list[str] = Field(default_factory=lambda: ["**"])
    pytest_paths: list[str] = Field(default_factory=list)
    integrate: bool = False
    permitted_tools: list[str] = Field(default_factory=lambda: ["text"])
    escalation_reason: str | None = None


class TaskResult(BaseModel):
    id: str
    status: Status
    model_requested: str
    model_actual: str | None = None
    role: Role | None = None
    effort_requested: str
    effort_actual: str | None = None
    output: str = ""
    changed_files: list[str] = Field(default_factory=list)
    tests: dict[str, object] = Field(default_factory=dict)
    usage: dict[str, object] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    diff: str = ""
    patch_path: str | None = None
    integrated: bool = False
    cost_usd: float = 0.0
    duration_s: float = 0.0


class Profile(str, Enum):
    """Engagement profile. Only `lab` and `observe` are enabled in M1."""

    LAB = "lab"
    OBSERVE = "observe"
    STAGING_VALIDATE = "staging-validate"
    PRODUCTION_VALIDATE = "production-validate"


class ObservationProfile(str, Enum):
    """Alias kept beside Profile for callers that read the brief's wording."""

    LAB = "lab"
    OBSERVE = "observe"


class FindingState(str, Enum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    VALIDATED = "validated"
    NOT_REPRODUCED = "not_reproduced"
    FIXED = "fixed"
    INCONCLUSIVE = "inconclusive"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ApprovalBlock(BaseModel):
    """Human approval. Models cannot fill this in."""

    approved: bool = False
    approved_by: str | None = None
    approved_at: str | None = None
    approved_manifest_sha256: str | None = None


class Engagement(BaseModel):
    """Engagement manifest. Every field is enforced outside the model."""

    id: str
    owner: str
    approver: str
    authorization_ref: str
    profile: Profile = Profile.LAB
    expires_at: str
    origins: list[str]
    methods: list[str] = Field(default_factory=lambda: ["GET"])
    path_prefixes: list[str] = Field(default_factory=lambda: ["/"])
    exclude_paths: list[str] = Field(default_factory=list)
    mutation_allowed: bool = False
    max_requests: int = 200
    max_rps: float = 1.0
    max_wall_seconds: float = 900.0
    max_concurrency: int = 1
    approval: ApprovalBlock = Field(default_factory=ApprovalBlock)


class CheckPlan(BaseModel):
    """What an adapter intends to do, declared before it does it."""

    adapter: str
    destinations: list[str]
    methods: list[str]
    mutations: bool = False
    estimated_requests: int = 0
    cleanup: str = "none"


class Finding(BaseModel):
    """Normalized finding shared by every adapter."""

    id: str
    title: str
    asset: str
    endpoint: str
    check_id: str
    check_version: str
    severity: Severity
    confidence: Confidence
    state: FindingState
    weakness_ref: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    detail: str = ""
    reproduction: list[str] = Field(default_factory=list)
    impact: str = ""
    limitations: list[str] = Field(default_factory=list)
    remediation: str = ""
    regression_recipe: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""


class Coverage(BaseModel):
    """What ran and what did not. Reports must show this."""

    targets_planned: list[str] = Field(default_factory=list)
    targets_visited: list[str] = Field(default_factory=list)
    requests_made: int = 0
    request_limit: int = 0
    truncated_pages: list[str] = Field(default_factory=list)
    skipped: list[dict[str, str]] = Field(default_factory=list)
    stop_reason: str = ""
    adapters: list[dict[str, object]] = Field(default_factory=list)
