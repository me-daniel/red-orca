# Red Orca / vsw — agent entry point

Requirements live in these files. Read only the one that owns the topic.

- `OPENCODE_BUILD_BRIEF.md` — product, integrations, contracts, scope, milestones
- `MODEL_ROUTING.md` — build-time delegates, effort, budgets, review
- `RED_MODEL_ROUTING.md` — assessment-time model roles (later cyber runs)

## Commands

```bash
uv run vsw doctor                 # toolchain, config, skills, routing, lab, browser
uv run vsw demo                   # deterministic mock demo
uv run vsw smoke --mock           # Claude advises, Codex implements, Codex reviews (mock)
uv run vsw smoke --live           # same flow through the real CLIs
uv run vsw lab up                 # local fixtures on 127.0.0.1:8787
uv run vsw run --target http://127.0.0.1:8787/vuln/   # observe, capture, report
uv run vsw findings               # list findings from the latest run
uv run vsw report                 # paths to the latest report
uv run vsw lab down
uv run vsw engagement validate --manifest configs/engagements/lab-local.yaml
uv run vsw delegate --model claude --label opus --effort medium --prompt "..." --dry-run
uv run vsw delegate --model codex --role implement --permitted-path 'src/**' --prompt "..."
```

## Invariants

- Build phase rejects cyber-only models (GPT-6 Sol, Luna) and unsupported efforts.
- Roles are fixed and enforced in the gateway: Claude advises in text only, Codex
  implements in a worktree and reviews read-only. Never ask one for the other's role.
- An implementation is inspected as a diff before `integrate`; out-of-bounds paths
  block integration.
- No push, merge, or publish without explicit approval.
- No live target work without an approved engagement manifest.
- Observation runs default to loopback; remote scope needs a human-approved manifest.
- Label mocks as mocks. Do not present simulated results as real.
- Default target scope is local fixtures only.
