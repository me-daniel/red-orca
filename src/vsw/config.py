"""Runtime configuration and hard limits."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields
from pathlib import Path

DEFAULT_LAB_PORT = 8789


def repo_root() -> Path:
    env = os.environ.get("VSW_ROOT")
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parents[2]


def load_env_file(path: Path | None = None) -> None:
    """Load KEY=VALUE pairs from `.env` without overriding the process env.

    Secrets stay in the environment; nothing is written to logs or reports.
    """
    path = path or repo_root() / ".env"
    if os.environ.get("VSW_NO_DOTENV"):
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError):
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        os.environ[key] = value


@dataclass(frozen=True)
class Limits:
    max_wall_seconds_per_run: float = 900.0
    max_delegate_calls_per_run: int = 8
    max_usd_per_run: float = 2.0
    per_call_timeout_seconds: float = 120.0
    implementation_timeout_seconds: float = 300.0
    coordinator_timeout_seconds: float = 120.0
    max_output_chars: int = 20000
    max_prompt_chars: int = 24000
    max_escalation_usd: float = 1.0
    max_task_budget_usd: float = 0.5

    def as_dict(self) -> dict[str, float | int]:
        return {f.name: getattr(self, f.name) for f in fields(self)}


_ENV_OVERRIDES = {
    "max_wall_seconds_per_run": ("VSW_MAX_WALL_SECONDS", float),
    "max_delegate_calls_per_run": ("VSW_MAX_DELEGATE_CALLS", int),
    "max_usd_per_run": ("VSW_MAX_USD", float),
    "per_call_timeout_seconds": ("VSW_PER_CALL_TIMEOUT", float),
    "implementation_timeout_seconds": ("VSW_IMPLEMENTATION_TIMEOUT", float),
    "coordinator_timeout_seconds": ("VSW_COORDINATOR_TIMEOUT", float),
    "max_output_chars": ("VSW_MAX_OUTPUT_CHARS", int),
    "max_prompt_chars": ("VSW_MAX_PROMPT_CHARS", int),
    "max_escalation_usd": ("VSW_MAX_ESCALATION_USD", float),
    "max_task_budget_usd": ("VSW_MAX_TASK_BUDGET_USD", float),
}


def load_limits(root: Path | None = None) -> Limits:
    """Load limits from configs/limits.json, then apply environment overrides."""
    root = root or repo_root()
    data: dict[str, object] = {}
    path = root / "configs" / "limits.json"
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path} must contain a JSON object")
        data.update(raw)

    for field_name, (env_name, cast) in _ENV_OVERRIDES.items():
        if os.environ.get(env_name):
            data[field_name] = cast(os.environ[env_name])

    known = {f.name for f in fields(Limits)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown limit keys: {sorted(unknown)}")
    return Limits(**data)  # type: ignore[arg-type]
