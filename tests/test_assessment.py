"""Lean multi-agent assessment tests."""

from __future__ import annotations

import json
from pathlib import Path

from vsw.assessment import run_assessment
from vsw.model_gateway import MockModelGateway


def test_mock_assessment_plans_observes_and_triages(tmp_path: Path, manifest, lab_server):
    target = f"{lab_server}/vuln/echo?q=%3Cb%3Evsw-assess%3C%2Fb%3E"
    report = run_assessment(
        manifest(),
        target,
        mode="mock",
        use_browser=False,
        root=tmp_path,
    )
    assert report["status"] == "pass"
    assert report["observation_status"] == "pass"
    assert report["plan"]["seeds"] == [target]
    assert report["plan"]["checks"] == ["passive-http"]
    assert report["triage"]["items"]
    assert report["model_calls"] == []

    run_dir = Path(report["run_dir"])
    for name in (
        "report.md",
        "findings.json",
        "coverage.json",
        "exchanges.json",
        "assessment.json",
        "assessment.md",
        "run.json",
    ):
        assert (run_dir / name).exists(), name
    assessment = json.loads((run_dir / "assessment.json").read_text(encoding="utf-8"))
    assert assessment["plan"]["seeds"] == [target]
    assert assessment["triage"]["items"]
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    finding_ids = {item["id"] for item in findings}
    assert {item["finding_id"] for item in assessment["triage"]["items"]} == finding_ids
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert run["assessment"]["status"] == "pass"
    markdown = (run_dir / "assessment.md").read_text(encoding="utf-8")
    assert "## Plan" in markdown
    assert "## Triage" in markdown
    assert "Triage is advisory" in markdown


def test_assessment_rejects_out_of_scope_plan_seed_and_unknown_triage(
    tmp_path: Path, manifest, lab_server
):
    target = f"{lab_server}/vuln/echo?q=assess-scope"
    gateway = MockModelGateway(
        {
            "plan": """```json
            {
              "focus": ["scope"],
              "seeds": [
                "http://127.0.0.2/",
                "http://127.0.0.1:8787/vuln/<redacted>",
                "TARGET"
              ],
              "checks": ["passive-http"],
              "notes": "test plan"
            }
            ```""".replace("TARGET", target),
            "triage": json.dumps(
                {
                    "items": [
                        {
                            "finding_id": "F-999",
                            "assessment": "needs_evidence",
                            "reason": "unknown finding",
                        }
                    ],
                    "summary": "test triage",
                }
            ),
        }
    )
    report = run_assessment(
        manifest(),
        target,
        mode="live",
        use_browser=False,
        root=tmp_path,
        gateway=gateway,
    )
    assert report["plan"]["seeds"] == [target]
    assert [item["seed"] for item in report["plan_rejected_seeds"]] == [
        "http://127.0.0.2/",
        "http://127.0.0.1:8787/vuln/<redacted>",
    ]
    assert report["unknown_finding_ids"] == ["F-999"]
    assert report["unmentioned_finding_ids"]
    assert len(report["model_calls"]) == 2


def test_mock_clean_control_triages_without_invented_findings(tmp_path: Path, manifest, lab_server):
    report = run_assessment(
        manifest(),
        f"{lab_server}/clean/",
        mode="mock",
        use_browser=False,
        root=tmp_path,
    )
    assert report["status"] == "pass"
    findings = json.loads(
        (Path(report["run_dir"]) / "findings.json").read_text(encoding="utf-8")
    )["findings"]
    assert findings == []
    assert report["triage"]["items"] == []
    assert "No triage summary" not in (Path(report["run_dir"]) / "assessment.md").read_text(
        encoding="utf-8"
    )
