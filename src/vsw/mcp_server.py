"""MCP stdio server exposing policy-checked build delegates to OpenCode."""

from __future__ import annotations

import json
import sys
from typing import Any

from .budget import Budget
from .coding_agent_gateway import CodingAgentGateway
from .config import load_limits, repo_root
from .domain import Phase, TaskEnvelope
from .policy import BUILD_ROUTES, RoutingDenied, resolve_build_route
from .util import utc_now

SERVER_NAME = "vsw-delegates"
SERVER_VERSION = "0.1.0"

_TOOLS = [
    {
        "name": "delegate_claude",
        "description": "Delegate build work to Claude Code (allowlisted models only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "label": {"type": "string", "default": "sonnet"},
                "effort": {"type": "string", "default": "high"},
                "budget_usd": {"type": "number", "default": 0.5},
                "timeout_seconds": {"type": "number"},
                "escalation_reason": {"type": "string"},
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delegate_codex",
        "description": "Delegate build work to Codex (allowlisted models only).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "label": {"type": "string", "default": "gpt-6.1-sol"},
                "effort": {"type": "string", "default": "high"},
                "budget_usd": {"type": "number", "default": 0.5},
                "timeout_seconds": {"type": "number"},
                "escalation_reason": {"type": "string"},
            },
            "required": ["prompt"],
            "additionalProperties": False,
        },
    },
    {
        "name": "policy_check",
        "description": "Resolve a delegate route without executing it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "family": {"type": "string"},
                "label": {"type": "string"},
                "effort": {"type": "string"},
                "budget_usd": {"type": "number", "default": 0.5},
                "escalation_reason": {"type": "string"},
            },
            "required": ["family", "label", "effort"],
            "additionalProperties": False,
        },
    },
    {
        "name": "pod_status",
        "description": "Report remaining budget, allowlist, and configured limits.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


class Server:
    def __init__(self) -> None:
        self.root = repo_root()
        self.limits = load_limits(self.root)
        self.budget = Budget(self.limits)
        self.gateway = CodingAgentGateway(self.limits, self.budget, root=self.root)

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params") or {}
        if request_id is None:
            return None
        if method == "initialize":
            return _ok(
                request_id,
                {
                    "protocolVersion": params.get("protocolVersion") or "2025-11-25",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": (
                        "Build delegates only. Cyber-only and unsupported routes are blocked. "
                        f"Limits: {json.dumps(self.limits.as_dict())}"
                    ),
                },
            )
        if method == "ping":
            return _ok(request_id, {})
        if method == "tools/list":
            return _ok(request_id, {"tools": _TOOLS})
        if method == "tools/call":
            return self._call(request_id, params)
        return _err(request_id, -32601, f"method not found: {method}")

    def _call(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if name in {"delegate_claude", "delegate_codex"}:
                family = "claude" if name == "delegate_claude" else "codex"
                envelope = TaskEnvelope(
                    id=f"mcp-{utc_now()}-{family}",
                    purpose="delegated build task",
                    phase=Phase.BUILD,
                    family=family,
                    label=str(
                        args.get("label") or ("sonnet" if family == "claude" else "gpt-6.1-sol")
                    ),
                    effort=str(args.get("effort") or "high"),
                    budget_usd=float(args.get("budget_usd") or self.limits.max_task_budget_usd),
                    timeout_s=float(
                        args.get("timeout_seconds") or self.limits.per_call_timeout_seconds
                    ),
                    escalation_reason=args.get("escalation_reason"),
                )
                result = self.gateway.run(envelope, str(args.get("prompt", "")))
                return _ok(request_id, _tool_result(result.model_dump(mode="json")))
            if name == "policy_check":
                try:
                    route = resolve_build_route(
                        str(args.get("family", "")),
                        str(args.get("label", "")),
                        str(args.get("effort", "")),
                        self.limits,
                        float(args.get("budget_usd") or self.limits.max_task_budget_usd),
                        args.get("escalation_reason"),
                    )
                    return _ok(
                        request_id,
                        _tool_result(
                            {
                                "decision": "allowed",
                                "route": route.key,
                                "cli_model": route.cli_model,
                            }
                        ),
                    )
                except RoutingDenied as exc:
                    return _ok(
                        request_id,
                        _tool_result({"decision": exc.status, "reason": exc.reason}),
                    )
            if name == "pod_status":
                return _ok(
                    request_id,
                    _tool_result(
                        {
                            "status": self.budget.status(),
                            "allowlist": sorted(":".join(k) for k in BUILD_ROUTES),
                            "checked_at": utc_now(),
                        }
                    ),
                )
            return _err(request_id, -32602, f"unknown tool: {name}")
        except Exception as exc:  # noqa: BLE001 - surface tool errors to the model
            return _ok(request_id, _tool_result({"error": f"{type(exc).__name__}: {exc}"}, True))


def _tool_result(payload: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
        "isError": is_error,
    }


def _ok(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _err(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main() -> int:
    server = Server()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response: dict[str, Any] | None
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _err(None, -32700, f"parse error: {exc}")
        else:
            response = server.handle(request)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
