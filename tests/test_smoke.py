import json
from pathlib import Path

from vsw.orchestrator import run_mock_demo
from vsw.smoke import run_smoke


def test_mock_smoke_passes_and_writes_report(tmp_path):
    report = run_smoke("mock", tmp_path)
    assert report["status"] == "pass"
    run_dir = Path(report["run_dir"])
    assert (run_dir / "report.json").exists()
    assert (run_dir / "clamp.py").exists()
    assert report["mode"] == "mock"
    data = json.loads((run_dir / "report.json").read_text())
    assert data["status"] == "pass"


def test_mock_demo_policy_and_smoke(tmp_path):
    report = run_mock_demo(tmp_path)
    assert report["status"] == "pass"
    decisions = {item["route"]: item["decision"] for item in report["policy"]}
    assert decisions["claude:sonnet:high"] == "allowed"
    assert decisions["codex:gpt-6-sol:max"] == "blocked"
    assert decisions["claude:opus:high"] == "blocked"
    assert Path(report["run_dir"], "report.md").exists()
