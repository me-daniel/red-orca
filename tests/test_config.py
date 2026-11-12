"""Local `.env` loading tests."""

from __future__ import annotations

import os
from pathlib import Path

from vsw.config import load_env_file


def test_load_env_file_sets_missing_values_only(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("VSW_TEST_KEY", raising=False)
    monkeypatch.setenv("VSW_KEEP", "from-env")
    path = tmp_path / ".env"
    path.write_text(
        "# comment\nVSW_TEST_KEY='quoted value'\nexport VSW_KEEP=from-file\n",
        encoding="utf-8",
    )
    load_env_file(path)
    assert os.environ["VSW_TEST_KEY"] == "quoted value"
    assert os.environ["VSW_KEEP"] == "from-env"


def test_load_env_file_is_optional(tmp_path: Path) -> None:
    load_env_file(tmp_path / "missing.env")
