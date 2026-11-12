"""Deterministic mock demo for M0. No network, no credentials."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .config import load_limits, repo_root
from .model_gateway import MockModelGateway
from .policy import RoutingDenied, resolve_build_route
from .smoke import run_smoke
from .util import utc_now


def run_mock_demo(root: Path | None = None) -> dict[str, Any]:
    root = root or repo_root()
    limits = load_limits(root)
    gateway = MockModelGateway()
    plan = gateway.complete("Plan the M0 mock demo.", "plan")

    policy = []
    for family, label, effort in (
        ("claude", "sonnet", "high"),
        ("codex", "gpt-6.1-sol", "high"),
    ):
        route = resolve_build_route(family, label, effort, limits, limits.max_task_budget_usd)
        policy.append({"route": route.key, "decision": "allowed"})
    for family, label, effort in (
        ("codex", "gpt-6-sol", "max"),
        ("claude", "opus", "high"),
    ):
        try:
            resolve_build_route(family, label, effort, limits, limits.max_task_budget_usd)
        except RoutingDenied as exc:
            policy.append(
                {
                    "route": f"{family}:{label}:{effort}",
                    "decision": exc.status,
                    "reason": exc.reason,
                }
            )

    smoke = run_smoke("mock", root)
    run_id = time.strftime("demo-%Y%m%d-%H%M%S", time.gmtime())
    report: dict[str, Any] = {
        "run_id": run_id,
        "stage": "M0",
        "mode": "mock",
        "started": utc_now(),
        "plan": plan.text,
        "policy": policy,
        "smoke": {
            "run_id": smoke["run_id"],
            "status": smoke["status"],
            "checks": smoke["checks"],
        },
        "status": smoke["status"],
    }
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (run_dir / "report.md").write_text(
        "\n".join(
            [
                f"# M0 mock demo — {run_id}",
                "",
                f"Status: **{report['status']}**",
                "",
                "## Plan",
                "",
                plan.text,
                "",
                "## Policy decisions",
                "",
                *[
                    f"- `{item['route']}`: {item['decision']}"
                    + (f" ({item.get('reason')})" if item.get("reason") else "")
                    for item in policy
                ],
                "",
                "## Smoke",
                "",
                f"- run: `{smoke['run_id']}`",
                f"- status: **{smoke['status']}**",
                *[f"- {c['name']}: {'PASS' if c['ok'] else 'FAIL'}" for c in smoke["checks"]],
                "",
                "This demo uses deterministic mocks. It makes no remote model calls.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    report["run_dir"] = str(run_dir)
    return report
