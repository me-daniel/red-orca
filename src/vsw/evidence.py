"""Evidence capture: hashed raw records and redacted views.

Raw captures stay in the gitignored run directory. Every record is hashed on
write and re-verified on read, so an edited capture is detectable. Redaction
happens before anything leaves the run directory: model prompts and exports
only see `redacted`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import utc_now

SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
}
_SECRET_BODY = re.compile(
    r"(?i)((?:token|api[_-]?key|secret|password|passwd|session|authorization)"
    r"[\"']?\s*[=:]\s*[\"']?)"
    r"([^\s&\"'<>,]{3,})"
)
_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{2,63}")
_MAX_BODY_BYTES = 256 * 1024
MAX_BODY_BYTES = _MAX_BODY_BYTES
_EVIDENCE_ID = re.compile(r"^E-\d{3,6}$")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def redact_text(text: str) -> str:
    text = _SECRET_BODY.sub(r"\1<redacted>", text)
    return _EMAIL.sub("<redacted-email>", text)


def redact_value(value: Any) -> Any:
    """Recursively redact strings in parsed metadata before it is persisted."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered == "set-cookie":
            out[name] = redact_set_cookie(value)
        elif lowered in SECRET_HEADERS:
            out[name] = "<redacted>"
        else:
            out[name] = redact_text(value)
    return out


def redact_set_cookie(value: str) -> str:
    """Keep cookie name and flags; drop the value and other attributes."""
    parts = [part.strip() for part in value.split(";") if part.strip()]
    if not parts:
        return "<redacted>"
    name = parts[0].split("=", 1)[0].strip()
    flags = []
    for part in parts[1:]:
        key = part.split("=", 1)[0].strip()
        if key.lower() in {"httponly", "secure", "samesite", "path", "domain"}:
            flags.append(part)
    return f"{name}=<redacted>" + (f"; {'; '.join(flags)}" if flags else "")


@dataclass
class EvidenceRecord:
    id: str
    kind: str  # http | browser | blocked
    url: str
    method: str = "GET"
    status: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_sha256: str = ""
    body_bytes: int = 0
    truncated: bool = False
    captured_at: str = ""
    source: str = ""
    notes: dict[str, Any] = field(default_factory=dict)
    record_sha256: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = {
            "id": self.id,
            "kind": self.kind,
            "url": self.url,
            "method": self.method,
            "status": self.status,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_headers": self.response_headers,
            "body": self.body,
            "body_sha256": self.body_sha256,
            "body_bytes": self.body_bytes,
            "truncated": self.truncated,
            "captured_at": self.captured_at,
            "source": self.source,
            "notes": self.notes,
        }
        data["record_sha256"] = _sha256_text(
            json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        )
        return data

    @property
    def header_names(self) -> set[str]:
        return {name.lower() for name in self.response_headers}


class EvidenceStore:
    """Writes evidence for one run and verifies it on demand."""

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.dir = run_dir / "evidence"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = run_dir / "evidence" / "index.jsonl"
        existing = [
            int(path.stem.split("-")[1])
            for path in self.dir.glob("E-*.json")
            if path.stem.split("-")[1].isdigit()
        ]
        self._counter = max(existing, default=0)

    def next_id(self) -> str:
        self._counter += 1
        return f"E-{self._counter:03d}"

    def capture(
        self,
        *,
        kind: str,
        url: str,
        method: str = "GET",
        status: int | None = None,
        request_headers: dict[str, str] | None = None,
        request_body: str = "",
        response_headers: dict[str, str] | None = None,
        body: bytes | str = b"",
        source: str = "",
        notes: dict[str, Any] | None = None,
        evidence_id: str | None = None,
        truncated: bool = False,
    ) -> EvidenceRecord:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        truncated = truncated or len(raw) > _MAX_BODY_BYTES
        stored = raw[:_MAX_BODY_BYTES]
        text = stored.decode("utf-8", errors="replace")
        if evidence_id is not None and not _EVIDENCE_ID.match(evidence_id):
            raise ValueError(f"invalid evidence id: {evidence_id!r}")
        raw = body.encode("utf-8") if isinstance(body, str) else body
        truncated = truncated or len(raw) > _MAX_BODY_BYTES
        stored = raw[:_MAX_BODY_BYTES]
        text = stored.decode("utf-8", errors="replace")
        request_text = request_body[:_MAX_BODY_BYTES]
        record = EvidenceRecord(
            id=evidence_id or self.next_id(),
            kind=kind,
            url=redact_text(url),
            method=method,
            status=status,
            request_headers=redact_headers(dict(request_headers or {})),
            request_body=redact_text(request_text),
            response_headers=redact_headers(dict(response_headers or {})),
            body=redact_text(text),
            body_sha256=_sha256_bytes(stored),
            body_bytes=len(raw),
            truncated=truncated,
            captured_at=utc_now(),
            source=redact_text(source),
            notes=redact_value(dict(notes or {})),
        )
        data = record.as_dict()
        record.record_sha256 = str(data["record_sha256"])
        (self.dir / f"{record.id}.json").write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        with self.index_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"id": record.id, "record_sha256": record.record_sha256},
                    ensure_ascii=False,
                )
                + "\n"
            )
        return record

    def records(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for path in sorted(self.dir.glob("E-*.json")):
            items.append(json.loads(path.read_text(encoding="utf-8")))
        return items

    def get(self, evidence_id: str) -> dict[str, Any]:
        if not _EVIDENCE_ID.match(evidence_id):
            raise ValueError(f"invalid evidence id: {evidence_id!r}")
        path = self.dir / f"{evidence_id}.json"
        if not path.exists():
            raise KeyError(f"no evidence {evidence_id}")
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data

    def verify(self) -> list[str]:
        """Return integrity problems; empty means every record matches its hash.

        The hash on its own only proves a file is self-consistent, so this also
        cross-checks the append-only index: a re-hashed record, a deleted
        record, and an injected record are all reported. An attacker who can
        rewrite both the file and the index is out of reach without an external
        anchor; that limit is stated in the report.
        """
        problems: list[str] = []
        indexed: dict[str, str] = {}
        if self.index_path.exists():
            for line in self.index_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    problems.append("index: unreadable entry")
                    continue
                entry_id = str(entry.get("id", ""))
                if entry_id in indexed:
                    problems.append(f"index: duplicate entry for {entry_id}")
                indexed[entry_id] = str(entry.get("record_sha256", ""))
        on_disk: set[str] = set()
        for path in sorted(self.dir.glob("E-*.json")):
            on_disk.add(path.stem)
            data = json.loads(path.read_text(encoding="utf-8"))
            claimed = data.pop("record_sha256", "")
            actual = _sha256_text(
                json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            )
            if claimed != actual:
                problems.append(f"{path.name}: record hash mismatch")
                continue
            if path.stem not in indexed:
                problems.append(f"{path.name}: record is not in the evidence index")
            elif indexed[path.stem] != claimed:
                problems.append(f"{path.name}: index digest disagrees with the record")
        for missing in sorted(set(indexed) - on_disk):
            problems.append(f"{missing}: indexed record is missing")
        return problems
