"""Typed task envelopes and results shared by every adapter."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


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
    diff_sha256: str = ""
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


class CoverageOutcome(str, Enum):
    """How a tested surface closed."""

    REPORTED = "reported"
    NO_ISSUE_FOUND = "no_issue_found"
    RULED_OUT = "ruled_out"
    NOT_APPLICABLE = "not_applicable"
    NEEDS_FOLLOW_UP = "needs_follow_up"


class CoverageRecord(BaseModel):
    """One surface/risk-area result.

    `source` records whether an agent claimed the result or the runtime observed
    it. Agents construct `CoverageEntry` (source fixed to `agent`); only the
    runtime module constructs the machine-observed subclass.
    """

    surface: str = Field(min_length=1)
    risk_area: str = Field(min_length=1)
    outcome: CoverageOutcome
    evidence: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    source: Literal["agent", "machine"] = "agent"
    agent: str = ""
    recorded_at: str = ""

    @model_validator(mode="after")
    def _negative_outcomes_need_evidence(self) -> CoverageRecord:
        if self.outcome == CoverageOutcome.NO_ISSUE_FOUND and not self.evidence_ids:
            raise ValueError("outcome 'no_issue_found' requires evidence_ids")
        if self.outcome in {
            CoverageOutcome.RULED_OUT,
            CoverageOutcome.NOT_APPLICABLE,
            CoverageOutcome.NEEDS_FOLLOW_UP,
        } and not self.evidence.strip():
            raise ValueError(f"outcome {self.outcome.value!r} requires evidence")
        return self


class CoverageEntry(CoverageRecord):
    """Agent-reported coverage. The source cannot be set by the caller."""

    source: Literal["agent"] = "agent"


class ReproStep(BaseModel):
    """One ordered, verbatim step captured when a finding was recorded."""

    request: str = ""
    response: str = ""
    expected: str = ""
    proves: str = ""
    exchange_id: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class Reproduction(BaseModel):
    """In-situ reproduction captured with a finding, not reconstructed later."""

    entry_point: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    steps: list[ReproStep] = Field(default_factory=list)
    provenance: str = ""


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
    cwe: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    exchange_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    detail: str = ""
    reproduction: list[str] = Field(default_factory=list)
    reproduction_detail: Reproduction | None = None
    impact: str = ""
    assumptions: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    confidence_rationale: str = ""
    severity_change_conditions: list[str] = Field(default_factory=list)
    code_locations: list[dict[str, object]] = Field(default_factory=list)
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
    entries: list[CoverageRecord] = Field(default_factory=list)
    stop_reason: str = ""
    adapters: list[dict[str, object]] = Field(default_factory=list)
