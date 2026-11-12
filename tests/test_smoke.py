import json
from pathlib import Path

from vsw.orchestrator import run_mock_demo
from vsw.smoke import run_smoke


def test_mock_smoke_passes_and_writes_report(git_repo):
    report = run_smoke("mock", git_repo)
    assert report["status"] == "pass", report["checks"]
    run_dir = Path(report["run_dir"])
    assert (run_dir / "report.json").exists()
    assert report["mode"] == "mock"
    assert report["roles"] == {"advice": "claude", "implement": "codex", "review": "codex"}
    assert [c["name"] for c in report["checks"]] == [
        "advice_completed",
        "advice_text_only",
        "implement_completed",
        "changed_files_within_bounds",
        "tests_pass",
        "review_completed",
        "review_verdict",
    ]
    data = json.loads((run_dir / "report.json").read_text())
    assert data["status"] == "pass"
    by_role = {item["role"]: item["model_requested"] for item in data["results"]}
    assert by_role == {
        "advice": "claude:opus",
        "implement": "codex:gpt-6.1-sol",
        "review": "codex:gpt-6.1-sol",
    }
    # The mock implementation is captured as a patch, never applied to the tree.
    assert not (git_repo / "clamp.py").exists()
    assert Path(report["artifacts"]["patch"]).exists()


def test_mock_demo_policy_and_smoke(git_repo):
    report = run_mock_demo(git_repo)
    assert report["status"] == "pass"
    decisions = {item["route"]: item["decision"] for item in report["policy"]}
    assert decisions["claude:sonnet:high"] == "allowed"
    assert decisions["codex:gpt-6-sol:max"] == "blocked"
    assert decisions["claude:opus:high"] == "blocked"
    assert Path(report["run_dir"], "report.md").exists()
