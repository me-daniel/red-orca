# Vorsprung Partners: security review

**13 November 2026 · Passive observation · Eight observations · Zero validated exploits**

The public pages have security hardening gaps and retain development-oriented
runtime features. This review did not demonstrate XSS, clickjacking, data theft,
or server compromise. The owner's known vulnerabilities remain **unverified in
this report** because their endpoints and reproduction evidence were not supplied.
Successful collection does not establish that the site is safe.

## Scope and method

Owner/approver: Daniel. Approved origins: `https://vorsprungpartners.com` and
`https://www.vorsprungpartners.com`, public GET-only observation through
20 November 2026. The [approved manifest](../../configs/engagements/vorsprungpartners.observe.yaml)
excludes sensitive paths and limits each run to 100 requests, one request per
second, and ten minutes. No forms, login, uploads, API calls, or active payloads
were tested.

The initial collector made one request; model-assisted observation made four.
The follow-up made eight public GETs, reviewing `/`, `/de/`, `/support.js`,
`/robots.txt`, `/sitemap.xml`, and `/.well-known/security.txt`. The last returned
404; the others returned 200. All seven full follow-up records passed integrity
checks; one additional request extracted dependency declarations only.

## Findings and fixes

All entries are **observed**, not validated. Severity reflects preliminary
hardening priority; confidence in the captured configuration/code is high.

| ID | Severity | Observation | Recommended action |
|---|---|---|---|
| F-001 | Medium | Both language pages lack a CSP response header. | Test a restrictive Content Security Policy in report-only mode, then enforce it. |
| F-002 | Low | Both pages lack `X-Frame-Options`; no CSP provides framing restrictions. | Set CSP `frame-ancestors` to the intended embedding policy; consider compatible `X-Frame-Options`. |
| F-003 | Low | Both pages lack `Referrer-Policy`. | Set an explicit policy appropriate to the site's navigation and privacy requirements. |
| F-004 | Low | Both pages lack `X-Content-Type-Options`. | Send `nosniff` with correct content types. |
| F-005 | Info | The initial capture identified a Google Fonts stylesheet dependency. | Consider self-hosting or document the privacy/availability dependency. |
| F-006 | Info | Both pages lack `Permissions-Policy`. | Disable browser capabilities the site does not need. |
| F-007 | Info | Public `support.js` retains `new Function` evaluation and global editor helpers. | Precompile production components and remove unnecessary editor hooks. |
| F-008 | Info | Runtime messaging omits sender origin/source checks and uses wildcard recipient origins. | Remove the bridge or restrict origins, source windows, and message schemas. |

**Impact limits:** F-007 has no demonstrated attacker-controlled input. F-008's
listener handles theme/probe messages, not arbitrary JavaScript updates; no
sensitive data leak or visible state change was demonstrated. Combining them
into a postMessage-to-XSS claim is unsupported. F-007 also complicates CSP
rollout because string evaluation requires an exception; avoid adding
`unsafe-eval` merely to preserve unnecessary runtime tooling.

## Dependency review

The script declares React/ReactDOM **18.3.1** and Babel standalone **7.29.0**,
with SRI values. Executed versions and SRI matches were not independently verified.
[React's RSC advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
does not establish exposure from client UMD declarations.
[Babel's SystemJS advisory](https://github.com/babel/babel/security/advisories/GHSA-fv7c-fp4j-7gwp)
and [source-map advisory](https://github.com/babel/babel/security/advisories/GHSA-4x5r-pxfx-6jf8)
require conditions not established here. No site CVE is confirmed. Review the
actual deployment lockfile and build settings; prefer precompilation as
[recommended by Babel](https://babeljs.io/docs/babel-standalone).

## Evidence and next steps

The [evidence summary](evidence/vorsprung-passive-review.json) preserves URLs,
timestamps, hashes, dependency declarations, and script excerpts. Follow-up
`E-001` and `E-006` support the page-header observations; `E-002`, lines 842–850,
1211–1223, 1740–1748, and 1871–1901, supports F-007; lines 1407–1419 and 1854–1868
support F-008. Evidence IDs are local to each run. Raw captures remain in ignored
`runs/` directories. The [homepage screenshot](evidence/vorsprung-home.jpg)
is visual context, not exploit proof.

The initial screenshot loaded external rendering dependencies under a separately
described allowance that is not bound by the two-origin manifest hash; record
that exception before repeating it. The follow-up made no such requests.
Model planning/triage was advisory and did not validate findings.

First reconcile the owner's known issues with their reproductions. Then fix the
observed configuration/runtime gaps and retest both language pages. Exploit,
authentication, authorization, private API, business-logic, and server dependency
coverage remains open; further validation needs an approved exact-check scope
or isolated staging target. This is a partial passive review, not a completed
penetration test.
