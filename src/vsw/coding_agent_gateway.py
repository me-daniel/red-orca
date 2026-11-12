"""CodingAgentGateway: bounded, policy-checked Claude/Codex delegation.

Roles are enforced here, not in prompts:

- Claude is a text-only adviser. It never gets tools, and if the repository
  working tree changes during an advice call the result is rejected.
- Codex implements in a separate worktree and reviews read-only. Its changes
  are captured as a diff and rejected when they fall outside `permitted_paths`
  before anything is integrated.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .budget import Budget, BudgetExceeded
from .config import Limits, repo_root
from .domain import Phase, Role, Status, TaskEnvelope, TaskResult
from .policy import Route, RoutingDenied, enforce_role, resolve_build_route
from .util import strip_ansi, truncate

MAX_PATCH_CHARS = 200_000


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
        self,
        envelope: TaskEnvelope,
        route: Route,
        prompt: str,
        timeout: float,
        workdir: Path | None = None,
    ) -> AdapterOutput: ...


class AdapterError(RuntimeError):
    pass


def _truncate(text: str, limit: int) -> str:
    return truncate(text, limit)[0]


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _git_status(root: Path) -> dict[str, str]:
    """Path -> porcelain status. Read-only: never restages the caller's index."""
    proc = _git("status", "--porcelain", "--untracked-files=all", cwd=root)
    entries: dict[str, str] = {}
    for line in (proc.stdout or "").splitlines():
        if len(line) < 4:
            continue
        path = line[3:].strip()
        if " -> " in path:  # rename: record the destination
            path = path.split(" -> ", 1)[1]
        entries[path] = line[:2]
    return entries


class ClaudeCliAdapter:
    """Text-only adviser: one turn, no tools, no repository writes."""

    def __init__(self, root: Path | None = None):
        self.root = root or repo_root()

    def run(
        self,
        envelope: TaskEnvelope,
        route: Route,
        prompt: str,
        timeout: float,
        workdir: Path | None = None,
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
                cwd=str(workdir or self.root),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AdapterError(f"timeout after {timeout:.0f}s") from exc
        elapsed = time.monotonic() - start

        payload: dict[str, Any] = {}
        if (proc.stdout or "").strip():
            try:
                payload = json.loads(proc.stdout)
            except json.JSONDecodeError:
                payload = {}
        text = str(payload.get("result") or proc.stdout or "").strip()
        usage = payload.get("usage") or {}
        if proc.returncode != 0 and not text:
            raise AdapterError(
                f"claude exited {proc.returncode}: {strip_ansi(proc.stderr or '')[-300:]}"
            )
        return AdapterOutput(
            text=text,
            # A text-only adviser never reports repository changes; the gateway
            # independently verifies this against the working tree.
            changed_files=[],
            cost_usd=float(payload.get("total_cost_usd") or 0.0),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            duration_s=elapsed,
            note="" if proc.returncode == 0 else f"rc={proc.returncode}",
        )


class CodexCliAdapter:
    """Uses the locally authenticated Codex CLI. Implementation and review."""

    def __init__(self, root: Path | None = None):
        self.root = root or repo_root()

    def run(
        self,
        envelope: TaskEnvelope,
        route: Route,
        prompt: str,
        timeout: float,
        workdir: Path | None = None,
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
        ]
        if envelope.role is Role.REVIEW:
            # Review is read-only; never let a reviewer edit the tree it reviews.
            cmd += ["--sandbox", "read-only"]
        cmd.append(prompt)
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(workdir or self.root),
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
    """Deterministic adapter for demos and tests.

    `files` simulates an implementer writing into its worktree; a mock that only
    returns text would correctly be rejected as "no file changes".
    """

    def __init__(
        self,
        responder: Callable[[TaskEnvelope, str], AdapterOutput],
        files: dict[str, str] | None = None,
    ):
        self.responder = responder
        self.files = dict(files or {})

    def run(
        self,
        envelope: TaskEnvelope,
        route: Route,
        prompt: str,
        timeout: float,
        workdir: Path | None = None,
    ) -> AdapterOutput:
        if self.files and workdir is not None and envelope.role is Role.IMPLEMENT:
            for name, content in self.files.items():
                target = workdir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
        return self.responder(envelope, prompt)


def _path_allowed(path: str, permitted: list[str]) -> bool:
    if path.startswith(("/", "\\")) or ".." in Path(path).parts:
        return False
    return any(fnmatch.fnmatch(path, pattern) for pattern in permitted)


def reject_outside_paths(changed: list[str], permitted: list[str]) -> list[str]:
    """Paths that must block integration."""
    return [path for path in changed if not _path_allowed(path, permitted)]


def apply_reviewed_patch(
    root: Path,
    patch_path: str,
    expected_sha256: str,
    review_verdict: str,
    tests_ok: bool,
) -> dict[str, Any]:
    """Apply a captured patch only when checks and review cover this exact diff.

    Three facts must agree: the patch on disk, the digest the reviewer saw, and
    the digest recorded when the implementation was captured.
    """
    verdict = (review_verdict or "").strip().upper()
    if not tests_ok:
        return {"integrated": False, "reason": "required tests did not pass"}
    if verdict != "APPROVED":
        return {
            "integrated": False,
            "reason": f"review verdict is {verdict or 'missing'}, not APPROVED",
        }
    path = Path(patch_path)
    if not path.is_absolute():
        path = root / path
    try:
        resolved = path.resolve()
        resolved.relative_to((root / "runs").resolve())
    except (OSError, ValueError):
        return {"integrated": False, "reason": "patch is not stored under runs/"}
    try:
        patch = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        return {"integrated": False, "reason": f"cannot read patch: {exc}"}
    actual = hashlib.sha256(patch.encode("utf-8")).hexdigest()
    if not expected_sha256 or actual != expected_sha256:
        return {"integrated": False, "reason": "patch content does not match the reviewed digest"}
    check = subprocess.run(
        ["git", "apply", "--check", "-"],
        cwd=str(root),
        input=patch,
        capture_output=True,
        text=True,
        check=False,
    )
    if check.returncode != 0:
        return {
            "integrated": False,
            "reason": f"patch does not apply cleanly: {strip_ansi(check.stderr)[-200:]}",
        }
    applied = subprocess.run(
        ["git", "apply", "-"],
        cwd=str(root),
        input=patch,
        capture_output=True,
        text=True,
        check=False,
    )
    if applied.returncode != 0:
        return {
            "integrated": False,
            "reason": f"git apply failed: {strip_ansi(applied.stderr)[-200:]}",
        }
    return {"integrated": True, "reason": "", "sha256": actual}


class WorktreeError(RuntimeError):
    pass


def _worktree_add(root: Path, name: str) -> Path:
    base = Path(tempfile.mkdtemp(prefix=f"vsw-wt-{name}-"))
    target = base / "tree"
    proc = _git("worktree", "add", "--detach", str(target), "HEAD", cwd=root)
    if proc.returncode != 0:
        raise WorktreeError(f"git worktree add failed: {strip_ansi(proc.stderr)[-300:]}")
    return target


def _worktree_remove(root: Path, target: Path) -> None:
    _git("worktree", "remove", "--force", str(target), cwd=root)
    shutil.rmtree(target.parent, ignore_errors=True)
    _git("worktree", "prune", cwd=root)


def _collect_changes(worktree: Path) -> tuple[list[str], str, bool]:
    """Changed paths, diff text, and whether the diff exceeded the bound.

    A truncated diff is not reviewable and not integrable: the coordinator
    cannot approve what it was not shown, and applying the full patch would
    apply text nobody reviewed.
    """
    _git("add", "-A", "-N", cwd=worktree)
    status = _git("status", "--porcelain", cwd=worktree)
    changed: list[str] = []
    for line in (status.stdout or "").splitlines():
        if len(line) < 4:
            continue
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        changed.append(path)
    full = _git("diff", "--binary", cwd=worktree).stdout or ""
    truncated = len(full) > MAX_PATCH_CHARS
    diff = full[:MAX_PATCH_CHARS] + "\n…[diff truncated]\n" if truncated else full
    _git("reset", "-q", cwd=worktree)
    return sorted(changed), diff, truncated


def _run_pytest(worktree: Path, paths: list[str], timeout: float) -> dict[str, object]:
    if not paths:
        return {}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", *paths],
            cwd=str(worktree),
            capture_output=True,
            text=True,
            timeout=min(timeout, 120.0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": "pytest timed out"}
    tail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
    return {"ok": proc.returncode == 0, "detail": tail[-1] if tail else "", "rc": proc.returncode}


def _result(envelope: TaskEnvelope, status: Status, **fields: Any) -> TaskResult:
    data: dict[str, Any] = {
        "id": envelope.id,
        "status": status,
        "model_requested": f"{envelope.family}:{envelope.label}",
        "role": envelope.role,
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

    # -- role enforcement -------------------------------------------------
    def _advice_guard(self, before: dict[str, str]) -> list[str]:
        after = _git_status(self.root)
        return sorted(set(after) - set(before))

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
            enforce_role(envelope.family, envelope.role.value)
        except RoutingDenied as exc:
            return _result(envelope, Status(exc.status), limitations=[exc.reason])

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

        implements = envelope.role is Role.IMPLEMENT
        try:
            self.budget.begin_call(route.key)
            timeout = self.budget.call_timeout(envelope.timeout_s, implementation=implements)
        except BudgetExceeded as exc:
            return _result(envelope, Status.BLOCKED, limitations=[str(exc)])

        adapter = self.adapters.get(route.family)
        if adapter is None:
            return _result(
                envelope,
                Status.UNAVAILABLE,
                limitations=[f"no adapter registered for {route.family}"],
            )

        if implements:
            return self._run_implementation(envelope, route, adapter, prompt, timeout)
        return self._run_advisory(envelope, route, adapter, prompt, timeout)

    # -- integration ------------------------------------------------------
    def integrate(
        self,
        result: TaskResult,
        review_verdict: str,
        reviewed_diff_sha256: str,
    ) -> TaskResult:
        """Apply a captured implementation only after an independent review.

        Kept out of `run`: a review happens after the diff exists, so integration
        is always a second, explicit step over the same captured patch.
        """
        reason = ""
        if result.status is not Status.COMPLETED:
            reason = "only a completed implementation can be integrated"
        elif reviewed_diff_sha256 != result.diff_sha256 or not result.diff_sha256:
            reason = "the review digest does not match the captured diff"
        else:
            # No configured checks means nothing failed; a recorded failure
            # always blocks integration.
            tests_ok = not result.tests or result.tests.get("ok") is True
            outcome = apply_reviewed_patch(
                self.root,
                result.patch_path or "",
                result.diff_sha256,
                review_verdict,
                tests_ok,
            )
            if outcome["integrated"]:
                return result.model_copy(update={"integrated": True})
            reason = str(outcome["reason"])
        return result.model_copy(
            update={
                "status": Status.BLOCKED,
                "integrated": False,
                "limitations": [*result.limitations, reason],
            }
        )

    def _run_advisory(
        self,
        envelope: TaskEnvelope,
        route: Route,
        adapter: Adapter,
        prompt: str,
        timeout: float,
    ) -> TaskResult:
        """Advice and review: no worktree, and the tree must stay untouched."""
        before = _git_status(self.root)
        started = time.monotonic()
        try:
            out = adapter.run(envelope, route, prompt, timeout, self.root)
        except AdapterError as exc:
            return _result(
                envelope,
                Status.FAILED,
                limitations=[str(exc)],
                duration_s=time.monotonic() - started,
            )
        self.budget.record(out.cost_usd)
        touched = self._advice_guard(before)
        limitation = out.note
        if touched:
            status = Status.BLOCKED
            limitation = (
                f"{envelope.role.value} role may not modify the repository; changed: {touched[:10]}"
            )
        elif not out.text.strip():
            status = Status.FAILED
            limitation = (limitation + "; empty output").strip("; ")
        else:
            status = Status.COMPLETED
        if out is None:  # pragma: no cover - guarded by the except above
            return _result(envelope, Status.FAILED, limitations=["adapter produced no output"])
        return _result(
            envelope,
            status,
            model_actual=f"{route.family}:{route.label}",
            effort_actual=route.effort,
            output=_truncate(out.text, self.limits.max_output_chars),
            changed_files=touched,
            usage={
                "input_tokens": out.input_tokens,
                "output_tokens": out.output_tokens,
                "cost_usd": out.cost_usd,
            },
            limitations=[limitation] if limitation else [],
            cost_usd=out.cost_usd,
            duration_s=out.duration_s,
        )

    def _run_implementation(
        self,
        envelope: TaskEnvelope,
        route: Route,
        adapter: Adapter,
        prompt: str,
        timeout: float,
    ) -> TaskResult:
        """Implementation: isolated worktree, captured diff, path check first."""
        started = time.monotonic()
        status = Status.FAILED
        limitation = ""
        changed: list[str] = []
        diff = ""
        diff_truncated = False
        diff_sha256 = ""
        tests: dict[str, object] = {}
        out: AdapterOutput | None = None
        try:
            worktree = _worktree_add(self.root, envelope.id)
        except WorktreeError as exc:
            return _result(envelope, Status.FAILED, limitations=[str(exc)])
        try:
            out = adapter.run(envelope, route, prompt, timeout, worktree)
            self.budget.record(out.cost_usd)
            changed, diff, diff_truncated = _collect_changes(worktree)
            bad = reject_outside_paths(changed, envelope.permitted_paths)
            patch_path: str | None = None
            integrated = False
            if diff.strip() and not diff_truncated:
                diff_sha256 = hashlib.sha256(diff.encode("utf-8")).hexdigest()
            if diff.strip() and not diff_truncated:
                safe_id = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in envelope.id)
                patch_dir = self.root / "runs" / safe_id
                patch_dir.mkdir(parents=True, exist_ok=True)
                patch_file = patch_dir / "impl.patch"
                patch_file.write_text(diff, encoding="utf-8")
                patch_path = str(patch_file)
            if bad:
                # Out-of-bounds code is never executed and never integrated.
                status = Status.BLOCKED
                limitation = f"changes outside permitted paths: {bad}"
            elif not changed:
                status = Status.FAILED
                limitation = "implementation produced no file changes"
            else:
                tests = _run_pytest(worktree, envelope.pytest_paths, timeout)
                if tests and not tests.get("ok"):
                    # Failing required checks is a failed implementation, not a
                    # completed one with a note.
                    status = Status.FAILED
                    limitation = f"pytest failed: {tests.get('detail', '')}".strip("; ")
                else:
                    status = Status.COMPLETED
                    limitation = out.note
        except AdapterError as exc:
            return _result(
                envelope,
                Status.FAILED,
                limitations=[str(exc)],
                duration_s=time.monotonic() - started,
            )
        finally:
            _worktree_remove(self.root, worktree)

        if out is None:  # pragma: no cover - guarded by the except above
            return _result(envelope, Status.FAILED, limitations=["adapter produced no output"])
        return _result(
            envelope,
            status,
            model_actual=f"{route.family}:{route.label}",
            effort_actual=route.effort,
            output=_truncate(out.text, self.limits.max_output_chars),
            changed_files=changed,
            tests=tests,
            diff=diff,
            diff_sha256=diff_sha256,
            patch_path=patch_path,
            integrated=integrated,
            usage={
                "input_tokens": out.input_tokens,
                "output_tokens": out.output_tokens,
                "cost_usd": out.cost_usd,
            },
            limitations=[limitation] if limitation else [],
            cost_usd=out.cost_usd,
            duration_s=time.monotonic() - started,
        )
