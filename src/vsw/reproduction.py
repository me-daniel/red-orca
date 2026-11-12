"""Reproduction redaction and verification.

A reproduction is only "captured" when its ordered steps resolve to real,
hash-verified HTTP exchanges in the same run. Export always redacts request and
response text first, even when the links do not verify.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .domain import Finding, Reproduction, ReproStep
from .evidence import redact_http_text, redact_text

_REQUEST_LINE = re.compile(r"^([A-Z]+)\s+(\S+)(?:\s+HTTP/\S+)?\s*$")


@dataclass(frozen=True)
class ReproductionCheck:
    verified: bool
    errors: list[str]


def _normalise(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def _request_target(text: str) -> tuple[str, str] | None:
    first = _normalise(text).split("\n", 1)[0]
    match = _REQUEST_LINE.match(first)
    if match is None:
        return None
    method, target = match.group(1).upper(), match.group(2)
    if target.startswith(("http://", "https://")):
        parts = urlsplit(target)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
    elif not target.startswith("/"):
        return None
    return method, target


def _path_and_query(target: str) -> tuple[str, str]:
    parts = urlsplit(target)
    return parts.path or "/", parts.query


def redact_reproduction(repro: Reproduction) -> Reproduction:
    """Return a redacted copy for reports and JSON export."""
    return Reproduction(
        entry_point=redact_http_text(repro.entry_point),
        prerequisites=[redact_text(item) for item in repro.prerequisites],
        steps=[
            ReproStep(
                request=redact_http_text(step.request),
                response=redact_http_text(step.response),
                expected=redact_text(step.expected),
                proves=redact_text(step.proves),
                exchange_id=step.exchange_id,
                evidence_ids=list(step.evidence_ids),
            )
            for step in repro.steps
        ],
        provenance=redact_text(repro.provenance),
    )


def verify_reproduction(
    repro: Reproduction, records: Mapping[str, dict[str, Any]]
) -> ReproductionCheck:
    """Check that every step links to a real exchange and evidence record.

    Verification is deliberately strict: a standard HTTP request line, matching
    method and target, the exchange id present in `evidence_ids`, stored request
    and response text, and the step text contained in that stored text. An
    unverifiable reproduction is reported as unverified, never captured.
    """
    errors: list[str] = []
    if not repro.steps:
        return ReproductionCheck(False, ["reproduction has no steps"])

    for index, step in enumerate(repro.steps, start=1):
        label = f"step {index}"
        if not step.exchange_id:
            errors.append(f"{label}: exchange_id is required")
        if not step.evidence_ids:
            errors.append(f"{label}: evidence_ids are required")
        if step.exchange_id and step.exchange_id not in step.evidence_ids:
            errors.append(f"{label}: exchange_id is not listed in evidence_ids")

        record = records.get(step.exchange_id) if step.exchange_id else None
        if record is None:
            errors.append(f"{label}: exchange {step.exchange_id!r} is not in the run evidence")
        else:
            if record.get("kind") != "http":
                errors.append(f"{label}: exchange is not an HTTP capture")
            method = str(record.get("method") or "").upper()
            parts = urlsplit(str(record.get("url") or ""))
            expected_target = (parts.path or "/", parts.query)
            parsed_request = _request_target(step.request)
            if parsed_request is None:
                errors.append(f"{label}: request is not a standard HTTP request line")
            else:
                request_method, request_target = parsed_request
                if request_method != method:
                    errors.append(f"{label}: request method does not match the exchange")
                if _path_and_query(request_target) != expected_target:
                    errors.append(f"{label}: request target does not match the exchange")

            stored_request = _normalise(str(record.get("request_text") or ""))
            if not stored_request:
                errors.append(f"{label}: exchange has no stored request text")
            elif _normalise(step.request) not in stored_request:
                errors.append(f"{label}: request text does not match the stored exchange")

            if not step.response:
                errors.append(f"{label}: response text is required")
            else:
                stored_response = _normalise(str(record.get("response_text") or ""))
                if not stored_response:
                    errors.append(f"{label}: exchange has no stored response text")
                elif _normalise(step.response) not in stored_response:
                    errors.append(f"{label}: response text does not match the stored exchange")

        for evidence_id in step.evidence_ids:
            if evidence_id not in records:
                errors.append(f"{label}: evidence {evidence_id!r} is not in the run evidence")

    if repro.entry_point:
        entry = _request_target(repro.entry_point)
        if entry is None:
            errors.append("entry point is not a method and target")
        else:
            first_request = _request_target(repro.steps[0].request)
            if first_request is not None and entry != first_request:
                errors.append("entry point does not match the first step")

    return ReproductionCheck(not errors, errors)


def finding_export(
    finding: Finding, records: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    """JSON-ready finding with reproduction redacted and link status explicit."""
    data = finding.model_dump(mode="json")
    detail = finding.reproduction_detail
    if detail is None:
        data["reproduction_verified"] = False
        return data
    redacted = redact_reproduction(detail)
    check = verify_reproduction(redacted, records)
    data["reproduction_detail"] = redacted.model_dump(mode="json")
    data["reproduction_verified"] = check.verified
    if check.errors:
        data["reproduction_errors"] = check.errors
    return data


def redact_export_payload(payload: Any) -> Any:
    """Defence in depth for JSON export: redact any reproduction_detail structure."""
    if isinstance(payload, dict):
        result: dict[str, Any] = {}
        for key, value in payload.items():
            if key == "reproduction_detail" and isinstance(value, dict):
                try:
                    detail = Reproduction.model_validate(value)
                except ValueError:
                    result[key] = _redact_unknown(value)
                else:
                    result[key] = redact_reproduction(detail).model_dump(mode="json")
            else:
                result[key] = redact_export_payload(value)
        return result
    if isinstance(payload, list):
        return [redact_export_payload(item) for item in payload]
    return payload


def _redact_unknown(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_unknown(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_unknown(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
