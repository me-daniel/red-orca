# Vorsprung Partners first passive run

Status: **DRAFT. No live request has been sent.**  
Target: `vorsprungpartners.com` (company-owned)  
Profile: `observe`  
Draft manifest: `configs/engagements/vorsprungpartners.observe.draft.yaml`

This is a preparation branch. It exists so the first authorized run can be
reviewed, approved, executed, and reported without expanding scope mid-run.

## Required before the first request

- [ ] Replace the draft `authorization_ref` with the written authorization or
      internal approval reference.
- [ ] Confirm the exact origins. The draft lists `https://vorsprungpartners.com`
      and `https://www.vorsprungpartners.com`; remove either if it is out of scope.
- [ ] Confirm or change the exclusion list. The draft excludes sensitive and
      state-changing paths, including `/admin`, `/wp-admin`, login/logout,
      account, cart, checkout, and `/api`.
- [ ] Confirm the request cap, rate, wall-clock cap, and expiry. The draft uses
      100 GETs, 1 request/second, 10 minutes, and expires 2026-11-20.
- [ ] Record the stop contact and data-retention policy. The current manifest
      schema does not carry separate fields for them, so put them in the
      authorization reference or extend the manifest schema before approval.
- [ ] Resolve the HTTPS decision. The current runner refuses HTTPS rather than
      tunnelling it. A live public site almost certainly uses HTTPS, so the run
      cannot start until a path-checked HTTPS transport or an approved local
      staging target is available.
- [ ] Add screenshot capture to the browser evidence path. The current browser
      adapter stores DOM/HTML and request metadata, not images. Visual findings
      need a hashed screenshot tied to the visited URL and finding.
- [ ] A human approves the manifest hash:
      `uv run vsw engagement approve --manifest <file> --approver <name>`.

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

No findings are documented here. The preliminary work was performed only against
the local lab fixture; see `docs/preliminary-lab-pentest.md`. Do not copy lab
findings into a Vorsprung report.
