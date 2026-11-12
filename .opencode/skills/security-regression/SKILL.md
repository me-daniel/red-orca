---
name: Security Regression
description: Write and verify a regression recipe that fails before a fix and passes after it
---

## Read first

- `OPENCODE_BUILD_BRIEF.md` §6 and §7 (finding schema, acceptance)
- `prompts/review.md` for the patch review contract

## Recipe shape

- **Finding ID** and check version
- **Preconditions**: fixture, seed data, accounts, build/commit
- **Command**: one fixed, non-interactive command
- **Expected failing observation** before the fix
- **Expected passing observation** after the fix
- **Cleanup**: reset state even on failure

## Rules

1. Run the recipe against the unpatched tree first and record the failure.
2. Apply the proposed patch only inside the permitted paths.
3. Run the identical recipe; record the pass.
4. Keep both transcripts. A pass without a prior failure is not regression evidence.
5. Without source access, give configuration guidance instead of inventing a patch.
6. A patch is proposed, never pushed or merged automatically.
