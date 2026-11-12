import inspect
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vsw import cli, lab
from vsw.config import DEFAULT_LAB_PORT
from vsw.scope import ScopeDenied, ScopeGuard, load_engagement, manifest_hash

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("args, expected", [([], DEFAULT_LAB_PORT), (["--port", "8799"], 8799)])
def test_lab_cli_port(monkeypatch, tmp_path, args, expected):
    calls = []

    def start_spy(root, port):
        calls.append((root, port))
        return {"port": port}

    monkeypatch.setenv("VSW_NO_DOTENV", "1")
    monkeypatch.setenv("VSW_ROOT", str(tmp_path))
    monkeypatch.setattr(lab, "start_lab", start_spy)
    result = CliRunner().invoke(cli.app, ["lab", "up", *args])
    assert result.exit_code == 0, result.output
    assert calls == [(tmp_path, expected)]


def test_default_lab_port_matches_approved_manifest():
    assert DEFAULT_LAB_PORT == 8789
    assert inspect.signature(lab.start_lab).parameters["port"].default == DEFAULT_LAB_PORT
    engagement = load_engagement(ROOT / "configs/engagements/lab-local.yaml")
    assert engagement.origins == [f"http://127.0.0.1:{DEFAULT_LAB_PORT}"]
    assert engagement.approval.approved_by == "daniel"
    assert engagement.approval.approved_at
    assert engagement.approval.approved_manifest_sha256 == manifest_hash(engagement)

    def no_resolution(*args):
        pytest.fail("the old origin must be rejected before DNS or network access")

    guard = ScopeGuard(engagement, resolver=no_resolution)
    with pytest.raises(ScopeDenied, match="origin .* is not approved"):
        guard.check("http://127.0.0.1:8787/vuln/")
