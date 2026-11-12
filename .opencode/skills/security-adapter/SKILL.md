---
name: Security Adapter
description: Add or review a security-engine adapter against the vsw adapter and evidence contracts
---

## Read first

- `OPENCODE_BUILD_BRIEF.md` §2 (priority repositories) and §5 (runtime contracts and scope)
- `src/vsw/coding_agent_gateway.py` for the bounded-delegation pattern

## Adapter contract

An adapter exposes:

1. `capabilities` — checks and target types it can run.
2. `validate_config` — reject incomplete config before any target request.
3. `plan` — destinations, methods, mutations, estimated load, cleanup.
4. `execute` — runs only the approved plan.
5. `cancel` — kills the process group and revokes network capability.
6. `normalize` — emits the common finding schema with evidence IDs.

## Rules

- The coordinator invokes fixed executables with validated argument arrays. Model text is never passed to a host shell.
- Engines receive the same policy, budgets, and evidence contract as every other adapter.
- Default to the `lab` profile. An engine that cannot enforce destination and method limits stays lab-only or disabled.
- Do not nest AntiFox and Strix agent loops.
- Pin the upstream commit or image in `upstreams.lock.json` and preserve its license notice.
- Normalize findings; do not invent reproduction steps from model prose.
