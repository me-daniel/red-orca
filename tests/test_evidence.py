import hashlib
import json
from pathlib import Path

import pytest

from vsw.evidence import EvidenceStore, redact_set_cookie, redact_text


def store(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "run")


def test_capture_redacts_secrets_but_keeps_cookie_flags(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(
        kind="http",
        url="http://127.0.0.1:8787/vuln/",
        status=200,
        request_headers={"Authorization": "Bearer super-secret-token"},
        response_headers={
            "Set-Cookie": "session=abc123; Path=/vuln",
            "X-Api-Key": "abc123",
        },
        body="contact admin@example.com password=hunter2 token=abcdef123456",
    )
    assert record.request_headers["Authorization"] == "<redacted>"
    assert record.response_headers["X-Api-Key"] == "<redacted>"
    assert "abc123" not in record.response_headers["Set-Cookie"]
    assert "session=<redacted>" in record.response_headers["Set-Cookie"]
    assert "Path=/vuln" in record.response_headers["Set-Cookie"]
    assert "admin@example.com" not in record.body
    assert "hunter2" not in record.body
    assert "<redacted>" in record.body


def test_cookie_flags_survive_redaction():
    redacted = redact_set_cookie("sid=s3cret; Path=/clean; HttpOnly; Secure; SameSite=Lax")
    assert redacted == "sid=<redacted>; Path=/clean; HttpOnly; Secure; SameSite=Lax"


def test_large_body_is_truncated_and_marked(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(
        kind="http",
        url="http://127.0.0.1:8787/big",
        status=200,
        body=b"a" * (300 * 1024),
    )
    assert record.truncated is True
    assert record.body_bytes == 300 * 1024
    assert len(record.body) == 256 * 1024
    assert len(record.body_sha256) == 64


def test_integrity_check_passes_for_fresh_evidence(tmp_path):
    evidence = store(tmp_path)
    evidence.capture(kind="http", url="http://127.0.0.1:8787/vuln/", status=200, body="ok")
    assert evidence.verify() == []


def test_forged_evidence_is_detected(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(
        kind="http", url="http://127.0.0.1:8787/vuln/", status=200, body="original"
    )
    path = evidence.dir / f"{record.id}.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"original"', '"edited"'), encoding="utf-8")
    problems = evidence.verify()
    assert problems and "hash mismatch" in problems[0]


def test_evidence_ids_are_sequential(tmp_path):
    evidence = store(tmp_path)
    first = evidence.capture(kind="http", url="u1", status=200, body="a")
    second = evidence.capture(kind="http", url="u2", status=200, body="b")
    assert (first.id, second.id) == ("E-001", "E-002")
    assert [item["id"] for item in evidence.records()] == ["E-001", "E-002"]


def test_json_style_secrets_are_redacted():
    assert redact_text('{"password": "hunter2"}') == '{"password": "<redacted>"}'
    assert redact_text("{'api_key': 'abcd1234'}") == "{'api_key': '<redacted>'}"


def test_url_query_credentials_are_redacted(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(
        kind="http",
        url="http://127.0.0.1:8787/vuln/echo?token=abcdef123456&q=keep",
        status=200,
        body="ok",
    )
    assert "abcdef123456" not in record.url
    assert "q=keep" in record.url


def test_notes_and_source_are_redacted(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(
        kind="http",
        url="http://127.0.0.1:8787/vuln/",
        status=200,
        body="ok",
        source="password=hunter2",
        notes={"reason": "session=abcdef123", "nested": {"email": "a@b.example"}},
    )
    assert "hunter2" not in record.source
    assert "abcdef123" not in record.notes["reason"]
    assert "a@b.example" not in record.notes["nested"]["email"]


def test_invalid_evidence_id_is_rejected(tmp_path):
    evidence = store(tmp_path)
    with pytest.raises(ValueError):
        evidence.capture(kind="http", url="u", status=200, evidence_id="../../escape")
    with pytest.raises(ValueError):
        evidence.get("../index")


def test_deleted_record_is_detected(tmp_path):
    evidence = store(tmp_path)
    first = evidence.capture(kind="http", url="u1", status=200, body="a")
    evidence.capture(kind="http", url="u2", status=200, body="b")
    (evidence.dir / f"{first.id}.json").unlink()
    problems = evidence.verify()
    assert any("missing" in item for item in problems)


def test_rehashed_forgery_is_detected_against_the_index(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(
        kind="http", url="http://127.0.0.1:8787/vuln/", status=200, body="original"
    )
    path = evidence.dir / f"{record.id}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["body"] = "forged"
    data.pop("record_sha256", None)
    digest = hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    data["record_sha256"] = digest
    path.write_text(json.dumps(data), encoding="utf-8")
    problems = evidence.verify()
    assert any("index digest disagrees" in item for item in problems)


def test_indexed_but_missing_record_is_detected(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(kind="http", url="u1", status=200, body="a")
    for path in evidence.dir.glob("E-*.json"):
        path.unlink()
    problems = evidence.verify()
    assert any(record.id in item and "missing" in item for item in problems)


def test_unreadable_record_is_detected_without_crashing(tmp_path):
    evidence = store(tmp_path)
    record = evidence.capture(kind="http", url="u1", status=200, body="a")
    (evidence.dir / f"{record.id}.json").write_text("{broken", encoding="utf-8")
    assert any("unreadable record" in item for item in evidence.verify())
    assert evidence.exchanges() == []
