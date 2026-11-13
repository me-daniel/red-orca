# M2 deterministic validation wiring

These checks use real HTTP against the owned loopback fixture, with no model
calls or inference cost. AntiFox integration and the Strix integration/comparison
are still pending; this work does not complete the full M2 milestone. No upstream
code, prompts, or install scripts are used here.

Start the lab and use the existing approved manifest unchanged:

```bash
uv run vsw lab up
uv run vsw engagement validate --manifest configs/engagements/lab-local.yaml
uv run vsw validate --manifest configs/engagements/lab-local.yaml --target http://127.0.0.1:8789/vuln/echo --check html-injection
uv run vsw validate --manifest configs/engagements/lab-local.yaml --target http://127.0.0.1:8789/clean/echo --check html-injection
uv run vsw validate --manifest configs/engagements/lab-local.yaml --target http://127.0.0.1:8789/vuln/open-redirect --check open-redirect
uv run vsw validate --manifest configs/engagements/lab-local.yaml --target http://127.0.0.1:8789/clean/open-redirect --check open-redirect
uv run vsw lab down
```

`html-injection` replaces `q` with an inert, unique HTML element marker. A
complete 200 HTML response containing that parsed element outside inert/raw text
contexts validates HTML injection. This is **not browser XSS**: there is no
browser execution, JavaScript payload, or proof of session impact. The vulnerable
echo inserts markup; the clean echo escapes it.

The parser is a conservative simple check, not browser-equivalent HTML5 parsing.
Any real `script` or `frameset` start tag outside already ignored raw text makes
the whole response unsupported for HTML validation. It clears even a previously
found marker and prevents later markers from validating, including after closing
tags. Script-bearing and frameset documents require browser verification; these
conservative false negatives do not establish that injection is absent. Escaped
tags, comments, and tags inside ignored raw text do not trigger this restriction.
Template and raw-text markers remain ignored. No browser execution or additional
parser dependency is used. Redirect checks are unaffected by these HTML limits.

HTML character encoding is checked against the actual bounded response bytes and
all transport Content-Type header values before lossy evidence decoding or HTML
parsing. The supported profile is strict UTF-8 with a single `utf-8` or `utf8`
charset label (case-insensitive, optionally double-quoted), or a UTF-8 BOM with
strict UTF-8 bytes. An ASCII/us-ascii label permits only ASCII bytes. With no
charset, only ASCII bytes are accepted unless a UTF-8 BOM explicitly identifies
UTF-8. Missing Content-Type still cannot validate an HTML finding: HTTP 200 and
`text/html` remain required.

This is a conservative profile, not browser-equivalent encoding sniffing. Other
labels, duplicate Content-Type headers, duplicate charset parameters (even equal
ones), malformed parameters, UTF-16/UTF-32 BOMs, invalid byte sequences, and a
UTF-8 BOM conflicting with an ASCII label are unsupported. NUL, ESC, SO/SI,
`~{`, and `+/v` byte sequences are also rejected conservatively to avoid
stateful-encoding ambiguity. Non-ASCII data without a declared UTF-8 charset or
UTF-8 BOM is unsupported; the check never guesses or silently changes encoding.

All lexical occurrences of `charset` or `http-equiv` in the response body are
unsupported, regardless of case. This deliberately rejects HTML meta encoding
declarations, including UTF-8 declarations consistent with the header, and can
also reject comments, inert text, or ordinary words containing those sequences.
It avoids a partial implementation of browser meta prescanning and its malformed
markup and precedence rules. These conservative false negatives need follow-up.
The encoding decision and supported decoded text are bound to the exact captured
record; changing record bytes, headers, or notes cannot authorize normalization.
Evidence capture retains its existing byte hash, byte count, redacted display,
and actual transport metadata; its UTF-8 replacement display is not the input to
HTML validation. Unsupported encoding keeps the captured exchange with an
explicit reason, marks the check incomplete, stops further checks, and reports
partial/needs_follow_up coverage with no validated finding for that exchange.

`open-redirect` replaces `to` with
`https://example.invalid/vsw-redirect-check`. A complete 3xx response whose
`Location` exactly matches that marker validates redirect control. HTML body
charset does not affect this header-only check. No redirect is followed, and the marker destination is never contacted. The clean endpoint
ignores `to` and always returns `Location: /clean/`.

Repeat `--check` to select both checks against the same explicit target. Each
selected check sends exactly one GET when completed; there is no discovery,
retry, passive crawl, or browser. Other query parameters are preserved. Empty,
unknown, or duplicate selections are blocked. Omitting validation selection from
`run_observation` preserves ordinary `run` and `assess` passive behavior.

Validation is restricted to approved, unexpired `lab` engagements, explicit HTTP
loopback targets, and allowed GET paths. The existing manifest permits `/vuln`
and `/clean` and excludes `/vuln/delete`. Approval does not bypass path, method,
DNS/address pinning, or expiry enforcement. Scope is checked before dispatch and
again after rate waits. The adapter retains the original approved manifest hash
and rechecks it before requests and during streaming; rewriting an approval hash
cannot expand an existing adapter's scope. Do not change the manifest without
human reapproval.

Seed and generated probe path/query targets must be ASCII and match HTTPX's
`raw_path` exactly before any request. Targets requiring transport normalization
(including dot segments or unescaped non-ASCII text) are blocked. Captures use
the actual response's request method, raw target and raw header tuples, plus the
actual response protocol, status, reason and raw headers. Textual request lines
use HTTP/1.1 because the fixed top-level HTTPX streaming transport disables HTTP/2.
The response version is captured independently, including HTTP/1.0 responses to
HTTP/1.1 requests. These are serializations of transport metadata, not packet
captures. Evidence URLs retain the approved logical origin and the
exact dispatched path/query; connections remain pinned and Host remains approved.

The shared guard enforces request/rate/wall-time limits (the checked-in manifest
sets 60 requests, 2 requests/second, and 180 seconds). Capture is size-bounded.
Cancellation is cooperative: cancellation, approval, expiry, and wall-time checks
run before dispatch, before and after every raw response chunk, and after the
response. This includes raw chunks that would produce no decoded output. Validation
requests identity encoding and rejects compressed or unsupported content encodings
before decoding or reading the body, keeping the body bound free of decompression
expansion. Ordinary passive observation retains its existing decoding behavior.
An in-flight blocking socket read cannot be immediately interrupted. Each blocking
I/O has a timeout of at most 10 seconds and the remaining allowed time at dispatch;
this is not a hard whole-download deadline. A stop detected around a read prevents
that chunk from being validated and prevents subsequent reads and checks. Aborted
streams are recorded as failures without claiming a complete HTTP capture.
Truncation, budget exhaustion, cancellation, HTTP 408/429/5xx, and other incomplete
exchanges stop further checks and cannot validate that exchange.
Earlier complete findings may remain in an incomplete run. CLI exit status is
nonzero for blocked, failed, or partial runs. A clean control returning no finding
only describes the selected check and captured response, not overall safety.

The command prints run ID/directory, status, finding/validated counts, evidence
integrity, and request count/limit/stop reason. The existing pipeline writes
`findings.json` (the full report payload), `report.md`, `run.json`, `coverage.json`,
`exchanges.json`, and hashed evidence. Validated findings require captured,
verified structured reproduction. Inspect `evidence_integrity`, adapter status,
and coverage stop reason before interpreting results.

Focused verification (real loopback sockets must be permitted):

```bash
PYTHONPATH=src uv run pytest tests/test_validation.py -q
```
