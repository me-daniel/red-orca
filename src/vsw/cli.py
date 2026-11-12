"""vsw command line interface."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

import typer

from .budget import Budget
from .coding_agent_gateway import CodingAgentGateway
from .config import load_limits, repo_root
from .domain import TaskEnvelope
from .orchestrator import run_mock_demo
from .policy import BUILD_ROUTES, RoutingDenied, resolve_build_route
from .smoke import run_smoke

app = typer.Typer(no_args_is_help=True, add_completion=False)

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

    _result(checks, "docker_for_m2", bool(shutil.which("docker")), "needed by AntiFox/Strix", False)

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
) -> None:
    """Run the M0 coding-and-review smoke task."""
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
    model: str = typer.Option(..., "--model", help="claude or codex"),
    label: str = typer.Option(..., "--label", help="opus, sonnet, or gpt-6.1-sol"),
    effort: str = typer.Option(..., "--effort", help="medium or high"),
    prompt: str = typer.Option(..., "--prompt"),
    budget_usd: float = typer.Option(0.5, "--budget-usd"),
    timeout: float = typer.Option(120.0, "--timeout"),
    escalation_reason: str | None = typer.Option(None, "--escalation-reason"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Resolve the route without calling a model."
    ),
) -> None:
    """Delegate one build task, or print the non-executing plan."""
    root = repo_root()
    limits = load_limits(root)
    budget = Budget(limits)
    envelope = TaskEnvelope(
        id="cli-delegate",
        purpose="cli delegated task",
        family=model,
        label=label,
        effort=effort,
        budget_usd=budget_usd,
        timeout_s=timeout,
        escalation_reason=escalation_reason,
    )
    if dry_run:
        try:
            route = resolve_build_route(model, label, effort, limits, budget_usd, escalation_reason)
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


if __name__ == "__main__":
    app()
