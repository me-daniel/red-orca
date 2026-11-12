# Build-time model routing

Companion to `OPENCODE_BUILD_BRIEF.md`. This file owns development routing only; `RED_MODEL_ROUTING.md` owns later assessment runs. Explicit user changes override these defaults. Model names are requested labels: verify exact IDs, versions, effort controls, and account access before invocation.

## Coordinator and allowed delegates

OpenCode owns the plan, task queue, budgets, and integration. Claude Code and Codex are bounded delegates, not competing top-level coordinators.

| Delegate | Effort | Default work |
|---|---|---|
| Claude Code / Opus | Medium | Architecture, ambiguous implementation, integration, review of Sol-authored changes |
| Claude Code / Sonnet | High | Well-specified implementation and tests |
| Codex / GPT-6.1 Sol | High | Independent plan/diff review, difficult implementation, stuck debugging |
| Claude Code / Opus | High | Occasional escalation with a named problem and bounded budget |

No other build model/effort pair is enabled by default. In particular, GPT-6 Sol and Luna Max are reserved for later cyber runs. Do not introduce Haiku, Terra, lower-effort Sonnet/Sol, or Opus xhigh/max through upstream skill defaults. Resolve Sonnet/Opus version labels at setup; never silently substitute an unavailable combination.

Prefer existing authorized Claude/Codex subscriptions for these delegates. Use Claude for routine implementation and reserve Codex capacity for independent review and difficult work, while retaining Sol's ability to implement. Do not assume fixed subscription-to-API value, unlimited automation, separate model quotas, or free usage. Inspect actual account limits; stop or queue on exhaustion. Paid API use requires an explicitly configured budget and endpoint.

## Workflow

1. Plan substantial work with Opus Medium; use concise acceptance criteria and file boundaries. Small edits need no separate plan document.
2. For architectural or consequential changes, obtain one fresh Sol High plan review before implementation.
3. Implement with Sonnet High or Opus Medium. Delegate difficult work to Sol High when useful; two failed attempts are a signal to change approach, not to repeat blindly.
4. Run relevant tests. If existing unrelated failures persist, record them and isolate the change's results.
5. Review nontrivial Claude-authored changes with Sol High; review Sol-authored changes with Opus Medium. Skip another model call for trivial, low-impact, already-verified edits.
6. Resolve review findings, rerun affected checks, and integrate only the verified patch.

For auth, scope enforcement, credentials, concurrency, or migrations, obtain independent Claude/Codex review plus relevant boundary tests. Use Opus High only for a specific unresolved issue. Local reversible development does not require a new human sign-off for every sensitive file; deployments, live engagements, and consequential external actions follow the brief's approval rules.

## Review contract

Supply the task/spec, base commit, diff, relevant surrounding code, interfaces, and test results. A diff alone is insufficient when correctness depends on context. Reviewers may request bounded additional reads. Run initial reviews independently; the coordinator can subsequently share findings to resolve disagreements.

Check correctness, edge cases, regressions, security, and test adequacy. Return `APPROVED`, `CHANGES_REQUESTED`, or `INCONCLUSIVE`, with file:line/evidence references and actionable findings. Review approval is not deployment or engagement authorization. Seek missing evidence before raising effort; escalation stays within the table.

## Implementation requirements

Implement through the brief's `CodingAgentGateway`, with separate worktrees, scoped permissions, structured results, timeouts, cancellation, and shared budgets. Verify current CLI flags using installed help and official documentation; do not commit guessed executable examples or modify global user configuration.

Create `configs/delegation.example.yaml` and `prompts/review.md`. Project-local Claude/Codex adapters may reference this file; do not duplicate routing tables into every skill or instruction file. pstack delegates must use the same model allowlist and worker limits. Preserve policy blocks rather than forwarding the refused operation to another model.

Acceptance: allowed build delegates pass local patch/review smoke tests where authenticated; mocks cover unavailable clients. Tests reject cyber-only models, unsupported efforts, forbidden file changes, and unbudgeted escalation. Report live and mock results separately.
