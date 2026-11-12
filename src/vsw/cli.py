"""vsw command line interface."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from .budget import Budget
from .coding_agent_gateway import CodingAgentGateway, apply_reviewed_patch
from .config import load_env_file, load_limits, repo_root
from .domain import Role, TaskEnvelope
from .model_gateway import (
    ModelRoute,
    ProviderConfig,
    ProviderUnavailable,
    default_model_config_path,
    gateway_for_route,
    load_model_config,
)
from .orchestrator import run_mock_demo, run_observation
from .policy import BUILD_ROUTES, RoutingDenied, enforce_role, resolve_build_route
from .smoke import run_smoke

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback()
def _bootstrap() -> None:
    """Load local `.env` settings before any command."""
    load_env_file(repo_root() / ".env")


REQUIRED_SKILLS = (
    "security-adapter",
    "security-evidence-review",
    "security-regression",
    "ponytail",
    "reverse-engineer-anything",
)


def _result(
    checks: list[dict[str, Any]], name: str, ok: bool, detail: str = "", required: bool = True
) -> None:
    checks.append({"name": name, "ok": ok, "detail": detail, "required": required})


def _config(root: Path) -> dict[str, Any]:
    data = json.loads((root / "opencode.jsonc").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@app.command()
def doctor(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Check the toolchain, config, skills, and routing policy."""
    root = repo_root()
    checks: list[dict[str, Any]] = []
    _result(checks, "python>=3.12", sys.version_info >= (3, 12), sys.version.split()[0])
    _result(checks, "uv", bool(shutil.which("uv")), shutil.which("uv") or "not found")
    _result(checks, "pyproject", (root / "pyproject.toml").exists(), "pyproject.toml")
    _result(checks, "uv.lock", (root / "uv.lock").exists(), "uv.lock")
    _result(
        checks, "upstreams.lock", (root / "upstreams.lock.json").exists(), "upstreams.lock.json"
    )

    for binary in ("opencode", "claude", "codex"):
        binary_path = shutil.which(binary)
        _result(checks, f"{binary}_cli", bool(binary_path), binary_path or "not found on PATH")

    try:
        config = _config(root)
        _result(checks, "opencode.jsonc", True, "opencode.jsonc")
    except Exception as exc:  # noqa: BLE001
        config = {}
        _result(checks, "opencode.jsonc", False, f"{type(exc).__name__}: {exc}")

    coordinator = config.get("agents", {}).get("coordinator", {}).get("model") or config.get(
        "model"
    )
    _result(
        checks,
        "coordinator_model",
        coordinator == "opencode/deepseek-v4.1-flash-free",
        str(coordinator),
    )
    _result(
        checks,
        "delegate_mcp",
        "delegates" in config.get("mcp", {}).get("servers", {}),
        "mcp.servers.delegates",
    )

    plugins = config.get("plugins", [])
    _result(
        checks,
        "pstack_plugin_pinned",
        any("pstack-claude#" in str(p) for p in plugins),
        str(plugins),
    )

    for skill in REQUIRED_SKILLS:
        path = root / ".opencode" / "skills" / skill / "SKILL.md"
        ok = path.exists() and "description:" in path.read_text(encoding="utf-8")
        _result(checks, f"skill:{skill}", ok, str(path))

    limits = load_limits(root)
    try:
        resolve_build_route("claude", "sonnet", "high", limits, limits.max_task_budget_usd)
        _result(checks, "policy:allowed", True, "claude:sonnet:high")
    except RoutingDenied as exc:
        _result(checks, "policy:allowed", False, exc.reason)
    try:
        resolve_build_route("codex", "gpt-6-sol", "max", limits, limits.max_task_budget_usd)
        _result(checks, "policy:cyber_blocked", False, "gpt-6-sol was allowed at build time")
    except RoutingDenied as exc:
        _result(checks, "policy:cyber_blocked", exc.status == "blocked", exc.reason)
    try:
        enforce_role("claude", "implement")
        _result(checks, "policy:role_split", False, "claude was allowed to implement")
    except RoutingDenied as exc:
        _result(checks, "policy:role_split", exc.status == "blocked", exc.reason)

    model_path = default_model_config_path(root)
    try:
        model_config = load_model_config(model_path)
        enabled = sum(1 for route in model_config.routes.values() if route.enabled)
        _result(
            checks,
            "model_config",
            True,
            f"{len(model_config.routes)} routes, {enabled} enabled: {model_path}",
        )
        seen_providers: set[str] = set()
        for route in model_config.routes.values():
            provider = model_config.providers[route.provider]
            if provider.name in seen_providers:
                continue
            seen_providers.add(provider.name)
            key_present = bool(os.environ.get(provider.api_key_env))
            _result(
                checks,
                f"model_key:{provider.name}",
                key_present,
                f"{provider.api_key_env} {'set' if key_present else 'missing'}; "
                "runtime routes stay disabled until enabled",
                required=False,
            )
        for route in model_config.routes.values():
            _result(
                checks,
                f"model_route:{route.name}",
                True,
                f"{route.provider}/{route.model} effort={route.effort} "
                f"{'enabled' if route.enabled else 'disabled'}",
                required=False,
            )
    except ProviderUnavailable as exc:
        _result(checks, "model_config", False, str(exc))

    _result(checks, "docker_for_m2", bool(shutil.which("docker")), "needed by AntiFox/Strix", False)

    from .lab import create_app
    from .scope import ScopeError, load_engagement

    _result(checks, "lab_fixture", callable(create_app), "vsw.lab.create_app")
    try:
        engagement = load_engagement(root / "configs" / "engagements" / "lab-local.yaml")
        _result(
            checks,
            "engagement:lab-local",
            True,
            f"{engagement.id} profile={engagement.profile.value}",
        )
    except ScopeError as exc:
        _result(checks, "engagement:lab-local", False, str(exc))

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            executable = pw.chromium.executable_path
        present = bool(executable) and Path(str(executable)).exists()
        _result(checks, "playwright_chromium", present, str(executable))
    except Exception as exc:  # noqa: BLE001 - report, do not crash the doctor
        _result(checks, "playwright_chromium", False, f"{type(exc).__name__}: {exc}")

    if json_output:
        typer.echo(json.dumps(checks, indent=2))
    else:
        for item in checks:
            label = "ok" if item["ok"] else ("BLOCKED" if not item["required"] else "FAIL")
            typer.echo(f"[{label:7}] {item['name']}: {item['detail']}")
    if not all(item["ok"] for item in checks if item["required"]):
        raise typer.Exit(code=1)


@app.command()
def demo() -> None:
    """Run the deterministic M0 mock demo. No network, no credentials."""
    report = run_mock_demo()
    typer.echo(
        json.dumps(
            {"run_id": report["run_id"], "status": report["status"], "run_dir": report["run_dir"]},
            indent=2,
        )
    )
    if report["status"] != "pass":
        raise typer.Exit(code=1)


@app.command()
def smoke(
    live: bool = typer.Option(False, "--live", help="Use real Claude/Codex delegates."),
    mock: bool = typer.Option(False, "--mock", help="Deterministic mock delegates (default)."),
) -> None:
    """Claude advises, Codex implements in a worktree, Codex reviews the diff."""
    if live and mock:
        typer.echo(json.dumps({"status": "error", "reason": "--live and --mock are exclusive"}))
        raise typer.Exit(code=2)
    report = run_smoke("live" if live else "mock")
    typer.echo(
        json.dumps(
            {
                "run_id": report["run_id"],
                "mode": report["mode"],
                "status": report["status"],
                "run_dir": report["run_dir"],
                "checks": report["checks"],
            },
            indent=2,
        )
    )
    if report["status"] != "pass":
        raise typer.Exit(code=1)


@app.command()
def delegate(
    model: str = typer.Option(..., "--model", help="claude (advice) or codex (implement/review)"),
    label: str = typer.Option(
        "opus", "--label", help="opus, sonnet, or gpt-6.1-sol (codex default)"
    ),
    effort: str = typer.Option("medium", "--effort", help="medium or high"),
    prompt: str = typer.Option(..., "--prompt"),
    role: str | None = typer.Option(None, "--role", help="advice, implement, or review"),
    permitted_path: Annotated[
        list[str] | None,
        typer.Option("--permitted-path", help="Glob an implementation may touch. Repeatable."),
    ] = None,
    pytest_path: Annotated[
        list[str] | None,
        typer.Option("--pytest-path", help="Test path to run in the worktree. Repeatable."),
    ] = None,
    budget_usd: float = typer.Option(0.5, "--budget-usd"),
    timeout: float | None = typer.Option(
        None, "--timeout", help="Defaults by role: 120s advice/review, 300s implement."
    ),
    escalation_reason: str | None = typer.Option(None, "--escalation-reason"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Resolve the route without calling a model."
    ),
) -> None:
    """Delegate one build task, or print the non-executing plan."""
    root = repo_root()
    limits = load_limits(root)
    budget = Budget(limits)
    family = model.strip().lower()
    # The default role follows the family so a plain call cannot cross the split.
    if role is None:
        role = "advice" if family == "claude" else "implement"
    if family == "codex" and label == "opus":
        label = "gpt-6.1-sol"
    if family == "claude" and label == "gpt-6.1-sol":
        label = "opus"
    envelope = TaskEnvelope(
        id="cli-delegate",
        purpose=f"cli delegated {role} task",
        family=family,
        label=label,
        effort=effort,
        role=Role(role),
        budget_usd=budget_usd,
        timeout_s=timeout
        or (
            limits.implementation_timeout_seconds
            if role == "implement"
            else limits.per_call_timeout_seconds
        ),
        permitted_paths=permitted_path or [],
        pytest_paths=pytest_path or [],
        escalation_reason=escalation_reason,
    )
    if dry_run:
        try:
            enforce_role(family, role)
            route = resolve_build_route(
                family, label, effort, limits, budget_usd, escalation_reason
            )
        except RoutingDenied as exc:
            typer.echo(json.dumps({"decision": exc.status, "reason": exc.reason}, indent=2))
            raise typer.Exit(code=1)
        typer.echo(
            json.dumps(
                {
                    "decision": "allowed",
                    "route": route.key,
                    "cli_model": route.cli_model,
                    "escalated": route.escalated,
                    "envelope": envelope.model_dump(mode="json"),
                },
                indent=2,
            )
        )
        return

    gateway = CodingAgentGateway(limits, budget, root=root)
    result = gateway.run(envelope, prompt)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
    typer.echo("--- budget ---")
    typer.echo(json.dumps(budget.status(), indent=2))
    if result.status.value != "completed":
        raise typer.Exit(code=1)


@app.command()
def integrate(
    patch: str = typer.Option(..., "--patch", help="Captured patch, stored under runs/."),
    diff_sha: str = typer.Option(..., "--diff-sha", help="Digest of the reviewed diff."),
    verdict: str = typer.Option(
        ..., "--verdict", help="APPROVED, CHANGES_REQUESTED, or INCONCLUSIVE"
    ),
    tests_ok: bool = typer.Option(False, "--tests-ok", help="Required tests passed."),
) -> None:
    """Apply a reviewed implementation patch, or refuse and say why."""
    outcome = apply_reviewed_patch(repo_root(), patch, diff_sha, verdict, tests_ok)
    typer.echo(json.dumps(outcome, indent=2))
    if not outcome["integrated"]:
        raise typer.Exit(code=1)


@app.command()
def policy() -> None:
    """Print the build allowlist and the cyber-only exclusions."""
    typer.echo(
        json.dumps(
            {
                "build_allowlist": sorted(":".join(k) for k in BUILD_ROUTES),
                "cyber_only_blocked": ["gpt-6-sol", "luna", "luna-max", "sol-max"],
                "efforts_blocked": ["low", "xhigh", "max"],
            },
            indent=2,
        )
    )


# -- runtime model routes ----------------------------------------------------

models_app = typer.Typer(no_args_is_help=True, help="Inspect or check runtime model routes.")
app.add_typer(models_app, name="models")


def _route_payload(
    name: str, route: ModelRoute, provider: ProviderConfig
) -> dict[str, object]:
    return {
        "name": name,
        "provider": provider.name,
        "base_url": provider.base_url,
        "model": route.model,
        "effort": route.effort,
        "max_tokens": route.max_tokens,
        "enabled": route.enabled,
        "api_key_env": provider.api_key_env,
        "key_present": bool(os.environ.get(provider.api_key_env)),
        "purpose": route.purpose,
    }


@models_app.command("list")
def models_list(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """List configured runtime routes. Secret values are never printed."""
    try:
        config = load_model_config(default_model_config_path(repo_root()))
    except ProviderUnavailable as exc:
        typer.echo(json.dumps({"status": "error", "reason": str(exc)}, indent=2))
        raise typer.Exit(code=1)
    rows = [
        _route_payload(name, config.routes[name], config.providers[config.routes[name].provider])
        for name in sorted(config.routes)
    ]
    if json_output:
        typer.echo(json.dumps({"routes": rows}, indent=2))
        return
    for row in rows:
        state = "enabled" if row["enabled"] else "disabled"
        key = "set" if row["key_present"] else "missing"
        typer.echo(
            f"{row['name']:18} {row['provider']}/{row['model']} "
            f"effort={row['effort']} max_tokens={row['max_tokens']} "
            f"{state} key={key} ({row['api_key_env']})"
        )


@models_app.command("check")
def models_check(
    route: str = typer.Argument(..., help="Route name from configs/models.yaml."),
) -> None:
    """Call one route once. Disabled routes are checkable but stay disabled."""
    limits = load_limits(repo_root())
    try:
        config = load_model_config(default_model_config_path(repo_root()))
        route_config = config.routes.get(route)
        if route_config is None:
            raise ProviderUnavailable(f"unknown model route: {route}")
        provider = config.providers[route_config.provider]
        gateway = gateway_for_route(config, route, limits=limits, allow_disabled=True)
    except ProviderUnavailable as exc:
        typer.echo(
            json.dumps(
                {"mode": "live", "status": "unavailable", "route": route, "reason": str(exc)},
                indent=2,
            )
        )
        raise typer.Exit(code=1)

    try:
        response = gateway.complete("Reply with the single word: pong", role="check")
    except ProviderUnavailable as exc:
        typer.echo(
            json.dumps(
                {
                    "mode": "live",
                    "status": "unavailable",
                    "route": route,
                    "provider": provider.name,
                    "model": route_config.model,
                    "reason": str(exc),
                },
                indent=2,
            )
        )
        raise typer.Exit(code=1)

    payload: dict[str, object] = {
        "mode": "live",
        "status": "ok" if response.usage else "no_usage",
        "route": route,
        "provider": provider.name,
        "requested_model": route_config.model,
        "response_model": response.model,
        "effort": route_config.effort,
        "enabled": route_config.enabled,
        "finish_reason": response.finish_reason,
        "latency_s": response.latency_s,
        "usage": response.usage,
        "cost_usd": response.cost_usd,
        "cost_measured": response.cost_measured,
        "billing_source": response.billing_source,
        "allowance_usd": response.allowance_usd,
        "text": response.text,
        "text_empty": not response.text.strip(),
        "note": response.note,
    }
    if not route_config.enabled:
        payload["route_state"] = (
            "disabled: check only; enable in configs/models.yaml after evaluation"
        )
    typer.echo(json.dumps(payload, indent=2))
    if not response.usage:
        raise typer.Exit(code=1)


# -- M1: lab, observation runs, findings, reports ---------------------------

lab_app = typer.Typer(no_args_is_help=True, help="Local disposable lab fixture.")
engagement_app = typer.Typer(no_args_is_help=True, help="Validate or approve engagement manifests.")
app.add_typer(lab_app, name="lab")
app.add_typer(engagement_app, name="engagement")

DEFAULT_MANIFEST = Path("configs/engagements/lab-local.yaml")
MANIFEST_OPTION = typer.Option(DEFAULT_MANIFEST, "--manifest", exists=True, dir_okay=False)
APPROVER_OPTION = typer.Option(..., "--approver", help="Human approving this scope.")


@lab_app.command("up")
def lab_up(port: int = typer.Option(8787, "--port")) -> None:
    """Start the lab fixture in the background."""
    from .lab import start_lab

    try:
        state = start_lab(repo_root(), port=port)
    except RuntimeError as exc:
        typer.echo(json.dumps({"status": "error", "reason": str(exc)}, indent=2))
        raise typer.Exit(code=1)
    typer.echo(json.dumps(state, indent=2))


@lab_app.command("down")
def lab_down() -> None:
    """Stop the lab fixture."""
    from .lab import stop_lab

    typer.echo(json.dumps(stop_lab(repo_root()), indent=2))


@lab_app.command("status")
def lab_status() -> None:
    """Report whether the lab fixture is running."""
    from .lab import state_path

    path = state_path(repo_root())
    if not path.exists():
        typer.echo(json.dumps({"running": False}, indent=2))
        return
    typer.echo(json.dumps({"running": True, **json.loads(path.read_text())}, indent=2))


@engagement_app.command("validate")
def engagement_validate(
    manifest: Path = MANIFEST_OPTION,
) -> None:
    """Check that a manifest exists, is unexpired, and its approval matches."""
    from .scope import ScopeError, load_engagement, manifest_hash

    try:
        engagement = load_engagement(manifest)
    except ScopeError as exc:
        typer.echo(json.dumps({"decision": "blocked", "reason": str(exc)}, indent=2))
        raise typer.Exit(code=1)
    typer.echo(
        json.dumps(
            {
                "decision": "allowed",
                "id": engagement.id,
                "profile": engagement.profile.value,
                "manifest_sha256": manifest_hash(engagement),
            },
            indent=2,
        )
    )


@engagement_app.command("approve")
def engagement_approve(
    manifest: Path = MANIFEST_OPTION,
    approver: str = APPROVER_OPTION,
) -> None:
    """Record approval over the current manifest content."""
    from .scope import ScopeError, approve_manifest, manifest_hash

    try:
        engagement = approve_manifest(manifest, approver)
    except ScopeError as exc:
        typer.echo(json.dumps({"decision": "blocked", "reason": str(exc)}, indent=2))
        raise typer.Exit(code=1)
    typer.echo(
        json.dumps(
            {
                "decision": "approved",
                "id": engagement.id,
                "manifest_sha256": manifest_hash(engagement),
            },
            indent=2,
        )
    )


@app.command()
def run(
    manifest: Path = MANIFEST_OPTION,
    target: str = typer.Option(
        None, "--target", help="In-scope URL; defaults to the first origin."
    ),
    browser: bool = typer.Option(True, "--browser/--no-browser", help="Use Playwright."),
) -> None:
    """Observe a scoped target, capture evidence, and write a report."""
    from .scope import ScopeError

    try:
        report = run_observation(manifest, target, use_browser=browser)
    except ScopeError as exc:
        typer.echo(json.dumps({"decision": "blocked", "reason": str(exc)}, indent=2))
        raise typer.Exit(code=1)
    typer.echo(
        json.dumps(
            {
                "run_id": report["run_id"],
                "status": report["status"],
                "run_dir": report["run_dir"],
                "findings": len(report["findings"]),
                "validated": sum(1 for item in report["findings"] if item["state"] == "validated"),
                "evidence_integrity": report["evidence_integrity"],
                "coverage": {
                    "requests_made": report["coverage"]["requests_made"],
                    "request_limit": report["coverage"]["request_limit"],
                    "stop_reason": report["coverage"]["stop_reason"] or "completed",
                },
            },
            indent=2,
        )
    )
    if report["status"] != "pass":
        raise typer.Exit(code=1)


def _run_dir(value: str | None) -> Path:
    from .scope import ScopeError

    root = repo_root()
    if value:
        given = Path(value)
        if given.is_absolute():
            path = given.resolve()
        else:
            candidates = [root / given, root / "runs" / given]
            path = next((item for item in candidates if item.exists()), candidates[0]).resolve()
    else:
        candidates = sorted((root / "runs").glob("obs-*"))
        if not candidates:
            typer.echo(json.dumps({"status": "error", "reason": "no observation runs"}, indent=2))
            raise typer.Exit(code=1)
        path = candidates[-1]
    if not (path / "findings.json").exists():
        raise ScopeError(f"{path} has no findings.json")
    return path


@app.command()
def findings(
    run: str = typer.Option(None, "--run", help="Run id or path; defaults to the latest."),
    state: str = typer.Option(None, "--state", help="Filter by finding state."),
    severity: str = typer.Option(None, "--severity", help="Filter by severity."),
) -> None:
    """List findings from an observation run."""
    from .scope import ScopeError

    try:
        path = _run_dir(run)
    except ScopeError as exc:
        typer.echo(json.dumps({"status": "error", "reason": str(exc)}, indent=2))
        raise typer.Exit(code=1)
    payload = json.loads((path / "findings.json").read_text(encoding="utf-8"))
    items = payload.get("findings", [])
    if state:
        items = [item for item in items if item.get("state") == state]
    if severity:
        items = [item for item in items if item.get("severity") == severity]
    typer.echo(
        json.dumps(
            {
                "run_id": payload.get("run_id"),
                "count": len(items),
                "findings": [
                    {
                        "id": item["id"],
                        "severity": item["severity"],
                        "state": item["state"],
                        "title": item["title"],
                        "endpoint": item["endpoint"],
                        "evidence": item["evidence_ids"],
                    }
                    for item in items
                ],
            },
            indent=2,
        )
    )


@app.command()
def report(
    run: str = typer.Option(None, "--run", help="Run id or path; defaults to the latest."),
) -> None:
    """Print the path to a run report."""
    from .scope import ScopeError

    try:
        path = _run_dir(run)
    except ScopeError as exc:
        typer.echo(json.dumps({"status": "error", "reason": str(exc)}, indent=2))
        raise typer.Exit(code=1)
    typer.echo(
        json.dumps(
            {
                "run_id": path.name,
                "markdown": str(path / "report.md"),
                "json": str(path / "findings.json"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    app()
