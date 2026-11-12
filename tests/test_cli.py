import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_opencode_config_and_skills():
    config = json.loads((ROOT / "opencode.jsonc").read_text(encoding="utf-8"))
    assert config["model"] == "opencode/deepseek-v4.1-flash-free"
    assert config["default_agent"] == "coordinator"
    assert config["agents"]["coordinator"]["model"] == "opencode/deepseek-v4.1-flash-free"
    assert "delegates" in config["mcp"]["servers"]
    assert any("pstack-claude#" in p for p in config["plugins"])

    required = (
        "security-adapter",
        "security-evidence-review",
        "security-regression",
        "ponytail",
        "reverse-engineer-anything",
    )
    for skill in required:
        path = ROOT / ".opencode" / "skills" / skill / "SKILL.md"
        assert path.exists(), path
        assert "description:" in path.read_text(encoding="utf-8")

    lock = json.loads((ROOT / "upstreams.lock.json").read_text(encoding="utf-8"))
    for name in ("ponytail", "pstack", "rea"):
        assert len(lock["upstreams"][name]["commit"]) == 40


def _run(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["VSW_ROOT"] = str(ROOT)
    return subprocess.run(
        [sys.executable, "-m", "vsw", *args],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_policy_command_lists_allowlist():
    proc = _run("policy")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "claude:sonnet:high" in data["build_allowlist"]
    assert "gpt-6-sol" in data["cyber_only_blocked"]


def test_delegate_dry_run_does_not_call_a_model():
    proc = _run(
        "delegate",
        "--model",
        "claude",
        "--label",
        "sonnet",
        "--effort",
        "high",
        "--prompt",
        "do it",
        "--dry-run",
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["decision"] == "allowed"
    assert data["cli_model"] == "sonnet"


def test_delegate_dry_run_rejects_cyber_model():
    proc = _run(
        "delegate",
        "--model",
        "codex",
        "--label",
        "gpt-6-sol",
        "--effort",
        "max",
        "--prompt",
        "do it",
        "--dry-run",
    )
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["decision"] == "blocked"


def test_delegate_dry_run_rejects_crossed_roles():
    proc = _run(
        "delegate",
        "--model",
        "claude",
        "--label",
        "opus",
        "--effort",
        "medium",
        "--role",
        "implement",
        "--prompt",
        "do it",
        "--dry-run",
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["decision"] == "blocked"
    assert "may not take" in payload["reason"]
