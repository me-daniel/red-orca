# Progress

Runnable now, with no remote provider credentials: the free DeepSeek coordinator, the
local Claude/Codex CLIs, and the local lab fixture.

## M0 — setup (done)

- Pinned dependencies (`uv.lock`), pstack plugin, Ponytail and REA skills, three
  project security skills.
- Build routing enforced: Claude Opus Medium, Claude Sonnet High, Codex Sol High;
  Opus High only with a named reason and a bounded budget; GPT-6 Sol/Luna, Terra,
  Haiku and low/xhigh/max efforts rejected during build.
- Deterministic mock demo passes without network.
- Roles are separated in the gateway, not in prompts: Claude Code is advice-only
  (one turn, no tools, repository writes blocked), Codex implements in a throwaway
  worktree and reviews read-only. A crossed role returns `blocked` before any
  adapter runs.
- Implementation results carry the changed files and diff; changes outside
  `permitted_paths` are rejected before anything is applied. Advice and review keep
  a 120 s per-call limit, implementation gets 300 s (`VSW_IMPLEMENTATION_TIMEOUT`).
- Live smoke (mock is the default): Claude advises, Codex implements `clamp` in a
  worktree, Codex reviews and approves.

## M1 — local HTTP observation (done, local fixtures only)

- Engagement manifests with hash-bound human approval; loopback-only `lab` profile
  and private-address-blocking `observe` profile.
- Scope guard covers redirects, browser subresources, methods, paths, exclusions,
  request budget, wall clock, and DNS/private-address escape.
- The guard returns a pinned address and both HTTP adapters connect to it. A hostname
  cannot pass the check with one address and connect with another (rebinding).
- Path prefixes and exclusions match on segment boundaries, so `/vuln` does not
  approve `/vulnerability`.
- Every proxied request is checked individually, not only the adapter plan. Mutating
  methods are refused unless the manifest approves mutations, and the proxy's
  connection handlers share one concurrency limit sized by `max_concurrency`; the
  rate limiter takes its slot under a lock.
- A loopback forward proxy sits between the browser and the network, because
  Playwright's request interceptor never sees a server-side redirect hop. Measured
  against a live off-list origin, Chromium routes redirect, meta-refresh, script, and
  iframe hops through the proxy and the origin receives zero requests; WebKit opens
  redirect hops directly, so the adapter refuses WebKit.
- Evidence is hashed on write, redacted before storage, size-bounded with an explicit
  truncation marker, and re-verified on every report.
- Deterministic analysis: missing headers, cookie flags, reflected parameters,
  external subresources, browser third-party requests, state-changing GET forms.
- Reports in Markdown and JSON with coverage, untested areas, evidence index, and
  escaped target content.
- Clean control produces zero findings; the vulnerable fixture produces a validated
  reflection plus observed header/cookie/data-flow findings.
- A run is `pass` only when evidence verifies and every requested adapter completed.
  Missing or failed adapters make it `partial` or `fail`; there is no clean bill from
  incomplete coverage.
- Integration is a separate call. A captured patch is applied only when its tests
  passed, its digest matches the diff the review saw, the review verdict is
  `APPROVED`, and the patch is stored under `runs/`.

## Live, mocked, blocked

| Item | State |
|---|---|
| DeepSeek coordinator via OpenCode | live |
| Claude Opus Medium advice, Codex Sol High implement/review | live (local CLI auth) |
| Lab fixture, passive HTTP, Playwright Chromium + scope proxy | live, loopback only |
| AntiFox / Strix | blocked: no container runtime |
| M2 validation checks | not started |
| Remote model routes (OpenRouter etc.) | unavailable without keys; unused in build |

## Known limits

- The `observe` profile enforces scope and rate limits but has only been exercised
  against loopback fixtures.
- `production-validate` and `staging-validate` profiles exist in the model but are
  rejected by `validate_engagement`; they are disabled until configured.
- Browser evidence is DOM/HTML plus request metadata; no screenshots yet.
- Browser observation is Chromium-only. WebKit stays available for manual use but is
  refused by the adapter while it opens redirect hops outside the proxy.
- HTTPS targets are refused, not tunnelled: a tunnel cannot be path-checked, so HTTPS
  scope enforcement needs a decision before it is enabled. M1 is therefore a local
  HTTP observation milestone, not remote HTTPS coverage; an HTTPS-only run cannot pass.
