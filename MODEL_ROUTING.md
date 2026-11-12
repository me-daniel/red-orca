# Build-time model routing

Companion to `OPENCODE_BUILD_BRIEF.md`. This file owns development routing only; `RED_MODEL_ROUTING.md` owns later assessment runs. Explicit user changes override these defaults. Model names are requested labels: verify exact IDs, versions, effort controls, and account access before invocation.

## Roles

Three roles, separated by responsibility and enforced in code, not in prompts:

| Role | Who | What it may do |
|---|---|---|
| Coordinator | OpenCode | Plan, sequencing, budgets, integration, adjudication. No delegated work. |
| Adviser | Claude Code | Read a brief and answer in text. One turn, no tools, no repository writes. |
| Implementer | Codex | Change the repository inside a separate worktree, inside permitted paths. |
| Reviewer | Codex | Read a diff and verdict it. Read-only sandbox; never edits. |

`ROLE_ALLOWLIST` in `src/vsw/policy.py` is the enforcement point. Claude cannot take `implement` or `review`; Codex cannot take `advice`. A request that crosses those lines returns `blocked` before any adapter runs, so a mis-worded prompt cannot move work to the wrong model.

## Allowed build routes

| Delegate | Effort | Default role | Work |
|---|---|---|---|
| Claude Code / Opus | Medium | advice | Unclear architecture or implementation decisions that are not cybersecurity-specific |
| Claude Code / Sonnet | High | advice | Cheaper second opinion; same limits as Opus |
| Codex / GPT-6.1 Sol | High | implement, review | Repository implementation and independent diff review |
| Claude Code / Opus | High | advice | Occasional escalation with a named problem and bounded budget |

No other build model/effort pair is enabled by default. In particular, GPT-6 Sol and Luna Max are reserved for later cyber runs. Do not introduce Haiku, Terra, lower-effort Sonnet/Sol, or Opus xhigh/max through upstream skill defaults. Resolve Sonnet/Opus version labels at setup; never silently substitute an unavailable combination.

Prefer existing authorized Claude/Codex subscriptions for these delegates. Do not assume fixed subscription-to-API value, unlimited automation, separate model quotas, or free usage. Inspect actual account limits; stop or queue on exhaustion. Paid API use requires an explicitly configured budget and endpoint.

## Workflow

1. OpenCode states the objective, acceptance criteria, and file boundaries, then decides whether the next step needs advice, implementation, or review.
2. Ask for advice only when the answer is genuinely unclear to the coordinator: an architecture choice, a tradeoff, a design with no precedent in the repo. Put the relevant context in the prompt; Claude sees no repository and has no tools. One advice round per question. If the answer is still unclear, the coordinator decides.
3. Implement with Codex. Each implementation runs in a throwaway `git worktree`, so a failed attempt cannot damage the user's working tree or index.
4. Read the returned changed files, diff, and test result. A change outside `permitted_paths` blocks integration; nothing is applied until the coordinator has seen the diff.
5. Review nontrivial changes with Codex in the `review` role, read-only, against the spec, the diff, and the test result. Review approval is not deployment or engagement authorization.
6. Resolve findings, rerun the affected checks, integrate only the verified patch, then verify on the artifact.

Two failed attempts at the same problem are a signal to change approach, not to repeat blindly.

For auth, scope enforcement, credentials, concurrency, or migrations, obtain independent review plus relevant boundary tests. Use Opus High only for a specific unresolved issue. Local reversible development does not require a new human sign-off for every sensitive file; deployments, live engagements, and consequential external actions follow the brief's approval rules.

## Limits

- Advice and review calls use `per_call_timeout_seconds` (120 s default).
- Implementation calls use `implementation_timeout_seconds` (300 s default, `VSW_IMPLEMENTATION_TIMEOUT`). Requested timeouts are capped by the role's limit and the remaining run wall clock.
- No per-model turn cap is applied inside a Codex call; the run budget bounds it. Do not raise delegate counts to compensate.
- `max_delegate_calls_per_run` (8), `max_usd_per_run` (2.0), and `max_task_budget_usd` (0.5) are unchanged.

## Review contract

Supply the task/spec, base commit, diff, relevant surrounding code, interfaces, and test results. A diff alone is insufficient when correctness depends on context. Reviewers may request bounded additional reads. Run initial reviews independently; the coordinator can subsequently share findings to resolve disagreements.

Check correctness, edge cases, regressions, security, and test adequacy. Return `APPROVED`, `CHANGES_REQUESTED`, or `INCONCLUSIVE`, with file:line/evidence references and actionable findings. Seek missing evidence before raising effort; escalation stays within the table.

## Implementation requirements

Implement through the brief's `CodingAgentGateway`, with separate worktrees, scoped permissions, structured results, timeouts, cancellation, and shared budgets. Verify current CLI flags using installed help and official documentation; do not commit guessed executable examples or modify global user configuration.

Create `configs/delegation.example.yaml` and `prompts/review.md`. Project-local Claude/Codex adapters may reference this file; do not duplicate routing tables into every skill or instruction file. pstack delegates must use the same model allowlist and worker limits. Preserve policy blocks rather than forwarding the refused operation to another model.

Acceptance: allowed build delegates pass local patch/review smoke tests where authenticated; mocks cover unavailable clients. Tests reject cyber-only models, unsupported efforts, forbidden file changes, role misuse, and unbudgeted escalation. Report live and mock results separately.
