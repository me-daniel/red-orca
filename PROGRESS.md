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

## Runtime model gateway (wired, routes disabled)

- `ModelGateway` implements the deterministic mock, OpenRouter, and generic
  OpenAI-compatible transports. The OpenCode Go subscription is the primary
  compatible endpoint; OpenRouter carries Gemini and the evaluable DeepSeek/GLM
  fallbacks. Sol and Luna are not gateway routes: later cyber runs call them
  through the local `codex exec` CLI.
- `configs/models.yaml` pins exact model IDs and efforts. Every route is
  disabled. `vsw models list` shows route state and whether the provider key is
  set without printing the key. `vsw models check <route>` calls one disabled
  route once and leaves it disabled.
- Each response records the provider-reported model, finish reason, latency,
  usage, charged cost, and any Go allowance. Provider errors redact the API key.
  A response without usage accounting is reported as `no_usage`.
- `.env` is loaded at startup. `OPENCODE_API_KEY` and `OPENROUTER_API_KEY` are
  optional; mock work needs no credentials.
- Live checks on 2026-11-12 (connectivity and accounting only, not fixture
  evaluations): Go `triage`, `kimi`, and `hy4`; OpenRouter `plan-openrouter`,
  `triage-openrouter`, and `gemini` returned usage and a measured cost or
  allowance. Go `plan` was initially refused because DeepSeek needed Global
  regions in the Console privacy settings; after the workspace region was set to
  Global, `vsw models check plan` returned usage and a Go allowance.
  `plan-openrouter` remains the explicit fallback.
- Sol and Luna are invoked through `codex exec` under the later cyber-run
  policy, not through this gateway. They use the Codex CLI's ChatGPT login and
  are not exercised in this build.

## Engine reference review (AntiFox, Strix)

- Read-only study of AntiFox `070f798` (AGPL-3.0) and Strix `0111915`
  (`strix-agent` 1.7.1, Apache-2.0). Notes and licensing boundary live in
  `docs/engine-reference.md`. No upstream code or prompt text was copied.
- Adopted natively: in-situ reproduction (`entry_point`, prerequisites, ordered
  verbatim request/response steps, provenance), traffic/exchange ids, a coverage
  ledger that keeps agent-reported and machine-observed provenance separate, and
  finding fields for CWE/CVSS, assumptions, counterevidence, confidence
  rationale, and severity-change conditions.
- Report rendering now prefers captured reproduction over later prose, fences
  target-controlled request/response text safely, and prints the coverage ledger.
- Deliberately not copied: AntiFox's missing scope layer, fail-open traffic
  capture, or AGPL code; Strix's full Kali tool fleet and agent SDK. Engines stay
  optional adapters.

## Live, mocked, blocked

| Item | State |
|---|---|
| DeepSeek coordinator via OpenCode | live |
| Claude Opus Medium advice, Codex Sol High implement/review | live (local CLI auth) |
| Lab fixture, passive HTTP, Playwright Chromium + scope proxy | live, loopback only |
| AntiFox / Strix | blocked: no container runtime |
| M2 validation checks | not started |
| Runtime model routes (OpenCode Go, OpenRouter) | wired; live-checked 2026-11-12; all routes disabled |

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
- Runtime routes are disabled by default. Enabling one requires a successful
  `vsw models check` and the labelled fixture comparison in `RED_MODEL_ROUTING.md`;
  a connectivity check alone is not an evaluation.
- Go DeepSeek requires Global regions in the Console privacy settings. If a
  workspace is not set to Global, `plan` fails closed; use `plan-openrouter` as
  the evaluated fallback.
- Go chat completions cannot represent the unified reasoning effort for
  Responses-native Luna and Gemini, so those routes use OpenRouter. Sending the
  field to Go returns a provider error rather than a silent downgrade.
