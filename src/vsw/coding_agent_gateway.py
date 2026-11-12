"""CodingAgentGateway: bounded, policy-checked Claude/Codex delegation."""

from __future__ import annotations

import fnmatch
import json
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .budget import Budget, BudgetExceeded
from .config import Limits, repo_root
from .domain import Phase, Status, TaskEnvelope, TaskResult
from .policy import Route, RoutingDenied, resolve_build_route
from .util import strip_ansi, truncate


@dataclass
class AdapterOutput:
    text: str
    changed_files: list[str] = field(default_factory=list)
    cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    duration_s: float = 0.0
    note: str = ""


class Adapter(Protocol):
    def run(
        self, envelope: TaskEnvelope, route: Route, prompt: str, timeout: float
    ) -> AdapterOutput: ...


class AdapterError(RuntimeError):
    pass


def _truncate(text: str, limit: int) -> str:
    return truncate(text, limit)[0]


class ClaudeCliAdapter:
    """Uses the locally authenticated Claude Code CLI. Text in, text out."""

    def __init__(self, root: Path | None = None):
        self.root = root or repo_root()

    def run(
        self, envelope: TaskEnvelope, route: Route, prompt: str, timeout: float
    ) -> AdapterOutput:
        binary = shutil.which("claude")
        if not binary:
            raise AdapterError("claude CLI not found on PATH")
        cmd = [
            binary,
            "-p",
            prompt,
            "--model",
            route.cli_model,
            "--effort",
            route.effort,
            "--output-format",
            "json",
            "--max-turns",
            "1",
            "--tools",
            "",
        ]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"timeout after {timeout:.0f}s") from exc
        elapsed = time.monotonic() - start
        stdout = strip_ansi(proc.stdout or "")
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise AdapterError(
                f"unparseable Claude output (rc={proc.returncode}): {stdout[:300]}"
            ) from exc
        text = str(payload.get("result") or "")
        usage = payload.get("usage") or {}
        return AdapterOutput(
            text=text,
            cost_usd=float(payload.get("total_cost_usd") or 0.0),
            input_tokens=int(usage.get("input_tokens") or 0)
            + int(usage.get("cache_read_input_tokens") or 0)
            + int(usage.get("cache_creation_input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            duration_s=elapsed,
            note="" if proc.returncode == 0 else f"rc={proc.returncode}",
        )


class CodexCliAdapter:
    """Uses the locally authenticated Codex CLI. Text in, text out."""

    def __init__(self, root: Path | None = None):
        self.root = root or repo_root()

    def run(
        self, envelope: TaskEnvelope, route: Route, prompt: str, timeout: float
    ) -> AdapterOutput:
        binary = shutil.which("codex")
        if not binary:
            raise AdapterError("codex CLI not found on PATH")
        cmd = [
            binary,
            "exec",
            "--skip-git-repo-check",
            "--json",
            "-m",
            route.cli_model,
            "-c",
            f'model_reasoning_effort="{route.effort}"',
            prompt,
        ]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"timeout after {timeout:.0f}s") from exc
        elapsed = time.monotonic() - start
        messages: list[str] = []
        input_tokens = 0
        output_tokens = 0
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "item.completed":
                item = event.get("item") or {}
                if item.get("type") == "agent_message" and item.get("text"):
                    messages.append(str(item["text"]))
            elif event.get("type") == "turn.completed":
                usage = event.get("usage") or {}
                input_tokens = int(usage.get("input_tokens") or 0)
                output_tokens = int(usage.get("output_tokens") or 0)
        return AdapterOutput(
            text="\n".join(messages).strip(),
            cost_usd=0.0,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration_s=elapsed,
            note="ChatGPT subscription; no marginal USD reported"
            if proc.returncode == 0
            else f"rc={proc.returncode}: {strip_ansi(proc.stderr or '')[-300:]}",
        )


class MockAdapter:
    """Deterministic adapter for demos and tests."""

    def __init__(self, responder: Callable[[TaskEnvelope, str], AdapterOutput]):
        self.responder = responder

    def run(
        self, envelope: TaskEnvelope, route: Route, prompt: str, timeout: float
    ) -> AdapterOutput:
        return self.responder(envelope, prompt)


def _path_allowed(path: str, permitted: list[str]) -> bool:
    if path.startswith(("/", "\\")) or ".." in Path(path).parts:
        return False
    return any(fnmatch.fnmatch(path, pattern) for pattern in permitted)


def _result(envelope: TaskEnvelope, status: Status, **fields: Any) -> TaskResult:
    data: dict[str, Any] = {
        "id": envelope.id,
        "status": status,
        "model_requested": f"{envelope.family}:{envelope.label}",
        "effort_requested": envelope.effort,
    }
    data.update(fields)
    return TaskResult.model_validate(data)


class CodingAgentGateway:
    def __init__(
        self,
        limits: Limits,
        budget: Budget,
        adapters: dict[str, Adapter] | None = None,
        root: Path | None = None,
    ):
        self.limits = limits
        self.budget = budget
        self.root = root or repo_root()
        self.adapters = adapters or {
            "claude": ClaudeCliAdapter(self.root),
            "codex": CodexCliAdapter(self.root),
        }

    def run(self, envelope: TaskEnvelope, prompt: str) -> TaskResult:
        if envelope.phase != Phase.BUILD:
            return _result(
                envelope,
                Status.BLOCKED,
                limitations=["build gateway only accepts the build phase"],
            )
        if len(prompt) > self.limits.max_prompt_chars:
            return _result(
                envelope,
                Status.BLOCKED,
                limitations=[f"prompt exceeds {self.limits.max_prompt_chars} chars"],
            )

        try:
            route = resolve_build_route(
                envelope.family,
                envelope.label,
                envelope.effort,
                self.limits,
                envelope.budget_usd,
                envelope.escalation_reason,
            )
        except RoutingDenied as exc:
            return _result(envelope, Status(exc.status), limitations=[exc.reason])

        try:
            self.budget.begin_call(route.key)
            timeout = self.budget.call_timeout(envelope.timeout_s)
        except BudgetExceeded as exc:
            return _result(envelope, Status.BLOCKED, limitations=[str(exc)])

        adapter = self.adapters.get(route.family)
        if adapter is None:
            return _result(
                envelope,
                Status.UNAVAILABLE,
                limitations=[f"no adapter registered for {route.family}"],
            )

        started = time.monotonic()
        try:
            out = adapter.run(envelope, route, prompt, timeout)
        except AdapterError as exc:
            return _result(
                envelope,
                Status.FAILED,
                limitations=[str(exc)],
                duration_s=time.monotonic() - started,
            )

        self.budget.record(out.cost_usd)
        bad_paths = [p for p in out.changed_files if not _path_allowed(p, envelope.permitted_paths)]
        limitation = out.note
        if bad_paths:
            status = Status.BLOCKED
            limitation = f"patch touches forbidden paths: {bad_paths}"
        elif not out.text.strip():
            status = Status.FAILED
            limitation = (limitation + "; empty output").strip("; ")
        else:
            status = Status.COMPLETED

        return _result(
            envelope,
            status,
            model_actual=f"{route.family}:{route.label}",
            effort_actual=route.effort,
            output=_truncate(out.text, self.limits.max_output_chars),
            changed_files=out.changed_files,
            usage={
                "input_tokens": out.input_tokens,
                "output_tokens": out.output_tokens,
                "cost_usd": out.cost_usd,
            },
            limitations=[limitation] if limitation else [],
            cost_usd=out.cost_usd,
            duration_s=out.duration_s,
        )
