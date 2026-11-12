import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_server(messages):
    env = dict(os.environ)
    env["VSW_ROOT"] = str(ROOT)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "mcp_delegates.py")],
        cwd=str(ROOT),
        env=env,
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def test_initialize_and_tool_catalog():
    responses = run_server(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25"},
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "pod_status", "arguments": {}},
            },
        ]
    )
    by_id = {item["id"]: item for item in responses}
    assert by_id[1]["result"]["serverInfo"]["name"] == "vsw-delegates"
    tools = {tool["name"] for tool in by_id[2]["result"]["tools"]}
    assert tools == {"delegate_claude", "delegate_codex", "policy_check", "pod_status"}
    status = json.loads(by_id[3]["result"]["content"][0]["text"])
    assert "claude:sonnet:high" in status["allowlist"]


def test_policy_check_blocks_cyber_model():
    responses = run_server(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "policy_check",
                    "arguments": {"family": "codex", "label": "gpt-6-sol", "effort": "max"},
                },
            }
        ]
    )
    payload = json.loads(responses[0]["result"]["content"][0]["text"])
    assert payload["decision"] == "blocked"


def test_oversized_prompt_is_blocked_without_calling_a_model():
    responses = run_server(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "delegate_claude",
                    "arguments": {"prompt": "x" * 30000},
                },
            }
        ]
    )
    payload = json.loads(responses[0]["result"]["content"][0]["text"])
    assert payload["status"] == "blocked"


def test_unknown_method_returns_jsonrpc_error():
    responses = run_server([{"jsonrpc": "2.0", "id": 9, "method": "nope/nope"}])
    assert responses[0]["error"]["code"] == -32601
