# Runtime model routing

Companion to `OPENCODE_BUILD_BRIEF.md`. This file owns model selection during explicitly initiated assessment runs; `MODEL_ROUTING.md` owns repository development. It does not grant target access or override the brief's engagement profiles.

## Scope and defaults

The Workbench runner owns scope, check approval, scheduling, tools, budgets, and evidence. Models propose actions and assess results. Start with the `observe` profile: approved source/configuration review, ordinary public responses, existing scanner evidence, and regression verification. Active validation requires the separate approved `lab`, `staging-validate`, or exact-check `production-validate` profile from the brief.

| Job | Requested model | Effort | Default |
|---|---|---|---|
| Routine planning and deployment analysis | DeepSeek V4.1 Flash 1017 | High | Primary open-model worker |
| Dependency/scanner triage | GLM-5.3-Flash | High | Use when it adds coverage or lowers measured cost |
| Consequential evidence/validation review | GPT-6 Sol via Codex | Max | Later cyber runs only |
| Independent review and evidence organization | GPT-6 Luna via Codex | Max | Later cyber runs only |

Sol and Luna use **Max from the start**, not high→xhigh escalation. These are requested labels; verify actual IDs and effective effort. Model choice never changes tool permissions. Begin a run with only needed roles, not every model. Closed-model reviewers receive only approved, sanitized packets and scoped tools.

Keep reasoning enabled at each role's specified level. Unsupported or unverified model/effort combinations return `unavailable`; no silent downgrade or substitution. A transport that cannot meet the requirement remains disabled until configured deliberately. Record model revision, endpoint, requested/effective effort, evidence IDs, elapsed time, and usage or unknown cost.

## Optional routes: disabled until evaluated

- GLM-5.3 High/Max or Kimi K3.1 Pro Max: a named difficult evidence question or disagreement.
- Apex Flash 1 / Feyospace v1.1: focused approved lab/staging investigation after endpoint, license, data-handling, effort, and accuracy checks. Routeway's Apex listing is a lead, not proof of a tested route or checkpoint revision.
- Gemini Argon and other media/document specialists: outside the initial build. Add only for a concrete unmet task with an evaluated advantage; do not create a large speculative model fleet.

OpenCode free routes may receive a small preference only after checking current availability, exact model/revision, data terms, effort, and tool compatibility. A free alias is not proof of equivalence to a named snapshot. Do not hardcode temporary free routes as required dependencies.

## Transport and configured routes

`configs/models.yaml` is the runtime route table. Routes are disabled until a
fixture comparison; `vsw models check <route>` calls a disabled route once without
enabling it. `plan` and `triage` are enabled for local lab/observe after the
2026-11-12 live evaluation; fallback and optional routes remain disabled.

`vsw assess --mode mock` runs the same plan → observe → triage loop without
credentials. `vsw assess --mode live` uses the enabled `plan` and `triage` routes;
`--evaluate` may call disabled routes for evaluation without enabling them. The
planner only selects registered adapter seeds inside the approved scope. Triage
is advisory: a model cannot change finding state, coverage, or scope.

| Route | Provider | Exact model | Effort | Use |
|---|---|---|---|---|
| `plan` | OpenCode Go | `deepseek-v4.1-flash` | High | Primary planning worker |
| `plan-openrouter` | OpenRouter | `deepseek/deepseek-v4.1-flash-1017` | High | Evaluated fallback |
| `triage` | OpenCode Go | `glm-5.3-flash` | High | Scanner and dependency triage |
| `triage-openrouter` | OpenRouter | `z-ai/glm-5.3-flash` | High | Evaluated fallback |
| `kimi` | OpenCode Go | `kimi-k3.1-pro` | Max | Named difficult-evidence route |
| `gemini` | OpenRouter | `google/gemini-4-argon` | High | Optional media and document specialist |
| `hy4` | OpenCode Go | `hy4` | High | Optional difficult-analysis route |

Sol and Luna are **not** in this table and not ModelGateway routes. Later cyber
runs invoke them through the local Codex CLI (`codex exec`), using the CLI's own
ChatGPT authentication. They do not use OpenCode, OpenRouter, or an OpenAI API
key in the normal path, and they remain later-cyber-run only.

Keys are read from `OPENCODE_API_KEY` and `OPENROUTER_API_KEY`. `.env` is
loaded at startup, is gitignored, and is never printed. The Go endpoint is
OpenAI-compatible chat completions at
`https://opencode.ai/inference/go/openai/v1`; OpenRouter is
`https://openrouter.ai/api/v1`.

Provider limits that affect a route:

- Go DeepSeek requires **Global** regions in the Console privacy settings. If a
  workspace is not set to Global, `plan` fails closed; use `plan-openrouter` for
  an evaluated comparison rather than treating the region refusal as a model
  failure.
- Go chat completions accept the unified `reasoning: {effort}` field for the
  open models used here. They reject it for the Responses-native Luna and
  Gemini models, so those routes use OpenRouter, which accepts it.
- Go reports charged cost in `usage.cost` (0 inside the subscription) and the
  consumed allowance in `usage.opencode.allowance`. Both are recorded; an
  allowance is not the same as a charge.
- Sol and Luna remain later-cyber-run reviewers and are called through
  `codex exec`, not this gateway. Configuring a transport does not authorize a
  cyber run or change tool permissions.

`vsw models check` reports the route, response model, finish reason, latency,
usage, charged cost, allowance, and whether usage was measured. A route with no
usage accounting is reported as `no_usage` and is not eligible for promotion.
A successful check is connectivity and accounting evidence, not a fixture
evaluation; label it as a live check, separately from mock results.

## Run sequence

1. Load an approved engagement and pin evidence/source revisions. Use a fixed checklist for one website; ask the primary model to adapt only when the system warrants it.
2. Assign separate bounded goals: source/access controls, deployment/public responses, dependencies/scanner evidence. With only a URL, explicitly mark unavailable source/deployment coverage.
3. Collect through registered checks and approved tools. Models cannot approve their own actions, install arbitrary tools, or expand scope.
4. Send consequential findings to Sol Max and/or Luna Max through the local `codex exec` CLI. Obtain independent first judgments when using both; give each relevant context and evidence, not the other reviewer's conclusions. Adjudicate disagreement with additional evidence or a bounded check.
5. Produce findings using the brief's common schema and states. Model agreement cannot promote a hypothesis to `validated` without the required observable evidence.
6. If source edits are authorized, open a separate remediation task routed through `MODEL_ROUTING.md`; use the selected build delegate in an isolated checkout. Runtime Sol/Luna may review the resulting evidence, but do not become repository-build delegates. Execute approved before/after regression checks and retain both results.

For missing headers, capture redirects and final HTML separately. Report the configuration observation without inferring exploitation. Use synthetic users/data for authorization and AI-agent tests. Keep unrelated records out of model packets.

## Operational rules and evaluation

Use the brief's gateway, isolation, concurrency, and shared budgets. Policy refusals remain `blocked`; independent approved goals may continue. Only preapproved operational fallback routes may handle outages/rate limits, with the same phase, data, and effort constraints. Never route a refused operation to another model to evade a decision.

Compare routes on identical labeled vulnerable/clean fixtures: accepted findings, missed issues, false positives, evidence accuracy, repeatability, tool errors, latency, and total cost. Compare a single reviewer with independent review only where consequential. Promote a route for a measured task-specific advantage, not a benchmark headline.

During repository development, use mock Sol/Luna workers. Live runtime acceptance is opt-in after credentials, data policy, and engagement approval are available; it is not a prerequisite for completing the local build.
