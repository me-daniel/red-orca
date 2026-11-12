# Red Orca / vsw — agent entry point

Requirements live in these files. Read only the one that owns the topic.

- `OPENCODE_BUILD_BRIEF.md` — product, integrations, contracts, scope, milestones
- `MODEL_ROUTING.md` — build-time delegates, effort, budgets, review
- `RED_MODEL_ROUTING.md` — assessment-time model roles (later cyber runs)

## Commands

```bash
uv run vsw doctor
uv run vsw demo
uv run vsw smoke --mock
uv run vsw delegate --model claude --label sonnet --effort high --prompt "..." --dry-run
```

## Invariants

- Build phase rejects cyber-only models (GPT-6 Sol, Luna) and unsupported efforts.
- No push, merge, or publish without explicit approval.
- No live target work without an approved engagement manifest.
- Label mocks as mocks. Do not present simulated results as real.
- Default target scope is local fixtures only.
