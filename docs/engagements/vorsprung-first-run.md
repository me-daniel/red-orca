# Vorsprung Partners first passive run

Status: **Passive run completed 2026-11-13.**  
Target: `vorsprungpartners.com` (company-owned)  
Profile: `observe`  
Approved manifest: `configs/engagements/vorsprungpartners.observe.yaml`  
Manifest SHA-256: `e1ae9cae7e582b10925edebb536ef683ab800ce26c9e7392a71e54493e2c4562`  
Results: `docs/engagements/vorsprung-first-run-results.md`

This branch records the first authorized passive run and the evidence needed to
draft a report. It used public GET requests only.

## Run readiness (completed)

- [x] Authorization reference recorded: verbal approval from owner daniel on
      2026-11-13 for public GET-only observation through 2026-11-20.
- [x] Origins confirmed: `https://vorsprungpartners.com` and
      `https://www.vorsprungpartners.com`.
- [x] Exclusions and limits set: sensitive/action paths excluded; 100 GETs,
      1 request/second, 10 minutes.
- [x] Data retention stated as local-only in the authorization reference. The
      stop contact is not a separate manifest field; record it in the report.
- [x] Passive HTTPS supported with a pinned address and SNI certificate
      verification. Browser HTTPS remains outside the normal browser adapter.
- [x] Visual capture completed as a separate one-off browser step with declared
      rendering dependencies; permanent adapter integration remains pending.
- [x] Manifest approved and validated at the hash above.

## Execution record

- Deterministic passive run: `obs-20261113-005235-000` — pass, one request,
  six observed findings, clean evidence integrity.
- Live multi-agent assessment: `assess-20261113-010337-000` — pass, DeepSeek
  plan + GLM triage, four observation requests, all six findings triaged
  `needs_evidence`.
- Visual evidence: `docs/engagements/evidence/vorsprung-home.jpg`, captured
  from the public homepage in Chromium after a no-click scroll pass.
- No validated vulnerability was found. The findings are hardening
  observations, not confirmed exploitable issues.

## Intended run

Only after the checklist passes:

1. Validate the approved manifest and confirm the manifest hash.
2. Run `vsw assess --mode live` with the approved target, or `vsw run` for a
   deterministic baseline. Start with passive GETs only; no mutations, forms,
   uploads, authentication, or API calls.
3. Capture hashed evidence for every response. Redact secrets before model
   calls and before any report or JSON export.
4. Capture one full-page screenshot per visited public page and one screenshot
   for each observed finding that has a visible representation.
5. Keep coverage honest: record blocked, skipped, truncated, and unvisited
   areas. A partial run is reported as partial.
6. Write the report from captured evidence only. No model prose may promote a
   finding to validated without a reproducible observable effect.

## Report outline

Use this structure when the run has real evidence:

- **Executive summary** — scope, dates, run ID, overall status, count by state.
- **Authorization and scope** — owner, approver, authorization reference,
  origins, methods, paths, exclusions, limits, expiry, stop contact.
- **Method** — passive observation only; tools, adapters, request counts,
  browser version, and limitations.
- **Coverage** — pages visited, skipped, blocked, truncated, and untested areas.
- **Findings** — stable finding ID, title, endpoint, severity, confidence,
  state, evidence IDs, reproduction, impact, limitations, remediation, and
  regression recipe.
- **Visual evidence** — screenshot per finding, caption, URL, capture time,
  SHA-256, and the corresponding evidence/exchange IDs.
- **Model-assisted review** — plan and triage roles, exact models and efforts,
  usage/allowance, and an explicit statement that triage is advisory.
- **Evidence integrity** — verification result and any withheld records.
- **Appendix** — raw request/response excerpts with secrets redacted, and the
  manifest hash.

## Current state

The passive run and live assessment are complete. See
`docs/engagements/vorsprung-first-run-results.md` for findings, evidence hashes,
the screenshot, model usage, and limitations. Do not copy lab findings into this
report, and do not treat observed hardening gaps as validated vulnerabilities.
