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

## Run sequence

1. Load an approved engagement and pin evidence/source revisions. Use a fixed checklist for one website; ask the primary model to adapt only when the system warrants it.
2. Assign separate bounded goals: source/access controls, deployment/public responses, dependencies/scanner evidence. With only a URL, explicitly mark unavailable source/deployment coverage.
3. Collect through registered checks and approved tools. Models cannot approve their own actions, install arbitrary tools, or expand scope.
4. Send consequential findings to Sol Max and/or Luna Max. Obtain independent first judgments when using both; give each relevant context and evidence, not the other reviewer's conclusions. Adjudicate disagreement with additional evidence or a bounded check.
5. Produce findings using the brief's common schema and states. Model agreement cannot promote a hypothesis to `validated` without the required observable evidence.
6. If source edits are authorized, open a separate remediation task routed through `MODEL_ROUTING.md`; use the selected build delegate in an isolated checkout. Runtime Sol/Luna may review the resulting evidence, but do not become repository-build delegates. Execute approved before/after regression checks and retain both results.

For missing headers, capture redirects and final HTML separately. Report the configuration observation without inferring exploitation. Use synthetic users/data for authorization and AI-agent tests. Keep unrelated records out of model packets.

## Operational rules and evaluation

Use the brief's gateway, isolation, concurrency, and shared budgets. Policy refusals remain `blocked`; independent approved goals may continue. Only preapproved operational fallback routes may handle outages/rate limits, with the same phase, data, and effort constraints. Never route a refused operation to another model to evade a decision.

Compare routes on identical labeled vulnerable/clean fixtures: accepted findings, missed issues, false positives, evidence accuracy, repeatability, tool errors, latency, and total cost. Compare a single reviewer with independent review only where consequential. Promote a route for a measured task-specific advantage, not a benchmark headline.

During repository development, use mock Sol/Luna workers. Live runtime acceptance is opt-in after credentials, data policy, and engagement approval are available; it is not a prerequisite for completing the local build.
