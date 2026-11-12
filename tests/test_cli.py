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


def _run(*args: str, env_overrides: dict[str, str] | None = None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["VSW_ROOT"] = str(ROOT)
    env["VSW_NO_DOTENV"] = "1"
    # Provider keys must not turn CLI tests into live calls.
    for name in ("OPENCODE_API_KEY", "OPENROUTER_API_KEY"):
        env.pop(name, None)
    if env_overrides:
        env.update(env_overrides)
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


def test_models_list_shows_disabled_routes_without_secrets():
    proc = _run("models", "list", "--json")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    routes = {route["name"]: route for route in data["routes"]}
    assert routes["plan"]["enabled"] is False
    assert routes["plan"]["model"] == "deepseek-v4.1-flash"
    assert routes["gemini"]["model"] == "google/gemini-4-argon"
    assert routes["plan"]["key_present"] is False
    assert "sk-" not in proc.stdout


def test_models_check_fails_closed_without_a_key():
    proc = _run("models", "check", "plan")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["status"] == "unavailable"
    assert "OPENCODE_API_KEY" in data["reason"]


def test_models_check_rejects_unknown_route():
    proc = _run("models", "check", "missing")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["status"] == "unavailable"
    assert "unknown model route" in data["reason"]


def test_report_lists_all_observation_artifacts(tmp_path):
    run_dir = tmp_path / "obs-test"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text("{}", encoding="utf-8")
    for name in ("report.md", "coverage.json", "exchanges.json", "run.json"):
        (run_dir / name).write_text("{}", encoding="utf-8")
    proc = _run("report", "--run", str(run_dir))
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert set(data) == {"run_id", "markdown", "json", "coverage", "exchanges", "run"}
    assert data["run_id"] == "obs-test"
