# Vorsprung Partners: first passive run

Date: 2026-11-13  
Target: `https://vorsprungpartners.com`  
Profile: `observe`  
Manifest: `configs/engagements/vorsprungpartners.observe.yaml`  
Manifest SHA-256: `e1ae9cae7e582b10925edebb536ef683ab800ce26c9e7392a71e54493e2c4562`  
Run: `obs-20261113-005235-000`  
Status: **pass**  
Evidence integrity: clean

This was a public, passive GET-only observation with the owner’s verbal approval.
No forms, uploads, authentication, API calls, mutations, or active payloads were
sent. The result is a draft input for a later report, not a complete assessment.

## Findings

| ID | Check | Severity | State | Observation |
|---|---|---|---|---|
| F-001 | `headers.content-security-policy` | medium | observed | No `Content-Security-Policy` response header |
| F-002 | `headers.frame-options` | low | observed | No `X-Frame-Options` response header |
| F-003 | `headers.referrer-policy` | low | observed | No `Referrer-Policy` response header |
| F-004 | `headers.x-content-type-options` | low | observed | No `X-Content-Type-Options` response header |
| F-005 | `browser.external_subresource` | info | observed | Page loads a font stylesheet from `fonts.googleapis.com` |
| F-006 | `headers.permissions-policy` | info | observed | No `Permissions-Policy` response header |

All six are **observed**, not validated. Missing headers alone do not prove
impact. No XSS, clickjacking, takeover, or data exposure was demonstrated.

## Evidence

- Exchange/evidence ID: `E-001`
- URL: `https://vorsprungpartners.com`
- HTTP status: `200`
- Captured: `2026-11-13T00:52:35Z`
- Body bytes: `109,506`
- Body SHA-256: `d48a1d82e92fdd1fe6e1a57f6749d0f3137c4f328304741b28d6ab9a0b3d3110`
- Record SHA-256: `edf0dcd616e8341cc46938612b31933b536417503ddd40d58adfaf02acae4d5e`

The capture is stored in the local run directory:

```text
runs/obs-20261113-005235-000/evidence/E-001.json
runs/obs-20261113-005235-000/findings.json
runs/obs-20261113-005235-000/report.md
runs/obs-20261113-005235-000/exchanges.json
```

## Live multi-agent assessment

Run: `assess-20261113-010337-000`  
Status: **pass**  
Observation: **pass**, 4 requests of 100  
Plan: DeepSeek V4.1 Flash, high effort  
Triage: GLM-5.3-Flash, high effort  
Model calls: 2; charged cost `$0.00`; Go allowance `0.0007839` for plan and
`0.00062055` for triage  
Artifacts: `runs/assess-20261113-010337-000/assessment.json` and
`assessment.md`

The planner selected three in-scope seeds (apex, apex with `/`, and `www`). The
triager marked all six findings `needs_evidence`, with reasons matching the
observed-only state. No finding was promoted to supported or validated. Triage
is advisory and did not change finding state, scope, or coverage.

## Visual evidence

![Vorsprung Partners homepage](evidence/vorsprung-home.jpg)

- Full-page screenshot, Chromium headless, 1440x900 viewport.
- Full PNG: `runs/obs-20261113-005235-000/evidence/screenshots/vorsprung-home.png`
- PNG SHA-256: `ff1baa919cd46c07d3b5e1f38a37b2423deb97c92814e6fa2e7fdb6ecbcd0fd8`
- Repository JPEG copy: `docs/engagements/evidence/vorsprung-home.jpg`
- JPEG SHA-256: `04906c54aa71161227b3e23ccee91bfaa5477e2fe0b05639c9496032addb9cb9`
- Capture method: one browser page load with a no-click scroll pass; GET-only
  requests capped at one per second; 38 same-origin/declared-dependency requests.

The screenshot documents the public homepage. It does not show a validated
vulnerability because none was found in this passive run.

## Third-party rendering dependencies

The public page’s `support.js` declares runtime dependencies on `unpkg.com` for
React, ReactDOM, and Babel. The page also loads images from
`static.wixstatic.com`, fonts from Google Fonts, and Wix static assets from
`static.parastorage.com`. The screenshot capture allowed those declared GET-only
rendering dependencies so the page could render; other third-party origins were
blocked. Those hosts were not security-tested.

This is a supply-chain observation for the report: the company homepage relies
on third-party CDNs for its client runtime and visual assets. The observed
`support.js` includes SRI values for React, ReactDOM, and Babel; verify that the
live versions and SRI values remain current.

## Coverage and limits

- Passive run requests: 1 of 100; stop reason: completed.
- One public page was captured. The site is a single-page marketing site; real
  internal links are mostly anchors or JavaScript templates, so the passive crawl
  did not discover additional pages.
- The passive run used only the company origins in the manifest. The screenshot
  step used the declared rendering dependencies listed above.
- TLS was verified against the approved hostname while connecting to the pinned
  address. Browser HTTPS remains outside the normal browser adapter.
- No authentication, account, API, form, upload, or active validation was tested.
- The results do not establish that the site is safe.

## Suggested report notes

- Present F-001 through F-006 as observations and hardening recommendations, not
  confirmed exploitable vulnerabilities.
- For CSP, describe the missing policy and recommend a tested policy; do not
  claim XSS without a reproduction.
- For frame embedding, recommend `frame-ancestors` in CSP and/or
  `X-Frame-Options` after confirming legitimate embedding requirements.
- For the external font, document the privacy/availability dependency and
  consider self-hosting or a documented exception.
- Include the screenshot as an appendix figure, with the hashes above.
- If active validation is authorized later, use a separate approved scope and
  capture a fresh reproduction; do not reuse these observed findings as proof.
