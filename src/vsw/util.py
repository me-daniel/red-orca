"""Shared helpers."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_run_dir(root: Path, prefix: str) -> tuple[str, Path]:
    """Reserve a run directory without ever reusing another run's evidence."""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    for sequence in range(1000):
        run_id = f"{prefix}-{stamp}-{sequence:03d}"
        run_dir = root / "runs" / run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            continue
        return run_id, run_dir
    raise RuntimeError(f"cannot reserve a unique {prefix} run directory")


def truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]", True


def audit_append(root: Path, record: dict[str, Any]) -> None:
    path = root / "runs" / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
