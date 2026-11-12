# Engine reference notes

Read-only review of AntiFox and Strix to extract their **behaviour and evidence
model** for `vsw`. This is not a code-reuse plan. No upstream code or prompt text
is copied into `vsw`.

| Project | Reviewed commit | Version | License | Role in `vsw` |
|---|---|---|---|---|
| [AntiFox](https://github.com/AntiFox-AI/antifox) | `070f798bf590667bc2a0a13c687dd87d8a4413bf` | Go 1.26.3 tree | AGPL-3.0 | Reference for stepwise reproduction, traffic-linked evidence, and graph-driven planning |
| [Strix](https://github.com/usestrix/strix) | `01119158f8f50027591cbae73f37cf0a2fea644d` | `strix-agent` 1.7.1 | Apache-2.0 | Reference for coverage provenance, finding schema, SARIF, sandbox limits, and budget parking |

AntiFox is copyleft. Copying its code into `vsw` would change `vsw`'s licensing
obligations. Study behaviour; implement independently. Strix is Apache-2.0, but
its prompts, skills, and sandbox image have their own terms. Keep the same
clean-room boundary for both.

## AntiFox

### Shape

AntiFox is a Go/PostgreSQL service with a Next.js UI. The useful part is its
reasoning model, not its stack.

- **Roles**: goals decomposer, human-facing main agent, event-driven planner,
  and workers. The planner is the only intent generator. A worker claims one
  intent, executes it, writes results back, and stops.
- **Two graphs**: a global asset graph and a per-task exploration graph. Nodes
  are `begin`, `goal`, `intent`, `fact`, `finding`, and `hint`; edges are
  `spawns`, `derived_from`, `yields`, and `proves`; anchors attach nodes to
  assets.
- **Activity ledger**: every tool call, tool result, text fragment, thinking
  fragment, and terminal result is recorded with a tool-use id and token usage.
- **Settlement**: when a worker hits a turn or wall-clock limit, a final round
  forces it to write back facts and findings instead of losing them.
- **Main agent**: records confirmed findings and steers the planner with hints
  or high-priority intents. It does not run the autonomous planning loop.

### Reproduction and evidence

The strongest idea is **in-situ reproduction**, captured when the finding is
recorded rather than reconstructed later.

A finding carries:

- `entry_point` — the triggering method and URL.
- `prerequisites` — accounts, roles, sessions, or prior steps, including how to
  create a test account from zero.
- ordered `steps`, each with verbatim `request`, verbatim `response`, `expected`,
  and `proves`.
- `provenance` — which exploration or intent produced the finding and what it
  depends on.

Findings also have screenshot evidence tied to a step index, and traffic links
tied to real recorded exchanges. The report renders the captured reproduction
first; AI-generated narrative is an overlay, not a replacement.

### Traffic correlation

AntiFox records every target request through a local MITM proxy into SQLite plus
a blob store, with a trigram full-text index over decoded bodies. A reproduction
step is resolved to a real exchange by:

1. method and path inside the task's time window;
2. chronological cursor, so repeated identical requests resolve in order;
3. body, query, and response discriminators, each applied only while at least
   one candidate remains;
4. the earliest remaining exchange at or after the previous step.

That `tryNarrow` behaviour is worth copying conceptually: an over-specific or
paraphrased field must not zero out a match that should succeed.

### Guard and limits

- Pre-tool gating blocks destructive and exfiltration-shaped shell commands.
- Post-tool attribution classifies results as `ok`, `blocked`, or `error` so the
  planner can change strategy instead of giving up at a WAF.
- User-configured intercept rules support `allow`, `deny`, and `ask`.
- AntiFox deliberately removed its Rules-of-Engagement scope layer. `vsw` must
  keep its own scope guard; model instructions are not scope enforcement.
- The proxy fails open for hosts it cannot intercept, leaving traffic
  unrecorded. `vsw` should fail closed or mark the gap; unrecorded traffic must
  not silently become evidence.

## Strix

### Shape

Strix is a Python `openai-agents` application with a root agent and a graph of
subagents. It adds three things worth adopting.

### Coverage ledger

A finding list answers "what is wrong"; it cannot answer "what was checked".
Strix records coverage entries with:

- `surface` — endpoint, route, file, or component.
- `risk_area` — what was being tested for.
- `outcome` — `reported`, `no_issue_found`, `ruled_out`, `not_applicable`, or
  `needs_follow_up`.
- `evidence` — required for the negative outcomes.
- `agent` and timestamp.

Coverage entries are **agent-reported**. Strix keeps them separate from
**machine-observed** facts such as which agents ran, which skills they carried,
and whether the run finished. A risk class with an assigned skill but no
coverage entry becomes a reported gap. That provenance split is the honest part:
a self-report must never be presented as a machine observation.

### Finding schema

Strix requires a finding to carry title, description, impact, target, technical
analysis, PoC description, PoC code, remediation, evidence, and assumptions.
Optional fields include CVE, CWE, CVSS breakdown, confidence, endpoint, method,
code locations, HTTP exchange ids, fix verification, and a proposed fix. It
deduplicates reports with a model judge when a deterministic key is insufficient.

The report artifacts are a useful model for `vsw`:

- `run.json` — run record, versions, auth mode, usage.
- `vulnerabilities/<id>.md`, `vulnerabilities.json`, `vulnerabilities.csv`.
- `findings.sarif` — CWE/STRIDE mapping, severity levels, locations, fixes.
- `coverage.json` — negative space with provenance.
- `penetration_test_report.md` — executive narrative.

CSV output neutralises spreadsheet formula prefixes. Markdown fences are sized
so attacker-influenced code cannot break out of the block. SARIF rejects absolute
paths and traversal.

### Sandbox and budget

- Per-scan Docker sandbox with resource caps for memory, CPUs, pids, shared
  memory, and bounded log files.
- Network isolation, host-gateway access for the target, and explicit device
  passthrough only when requested.
- Bind-mount and extra-file paths are validated against traversal and collision
  with the source tree.
- Scan-wide USD budget with `stop` and `pause` policies; agents park before the
  next model call and can resume or extend.
- Subscription auth is recorded as zero marginal cost rather than pretending the
  call was free.

## What `vsw` should adopt

1. **Exploration graph** with typed nodes and edges, anchored to assets.
2. **In-situ reproduction** with entry point, prerequisites, ordered verbatim
   steps, and provenance.
3. **Traffic-linked evidence** by exchange id, resolved with the ordered
   cursor and non-destructive narrowing rules.
4. **Coverage ledger** with agent-reported versus machine-observed provenance,
   and explicit gaps.
5. **Finding schema** with assumptions, counterevidence, confidence rationale,
   CWE/CVSS, code locations, and fix verification.
6. **Report artifacts** in Markdown, JSON, and SARIF, with safe CSV and safe code
   fences.
7. **Settlement** on budget exhaustion so facts and findings are written back.
8. **Budget parking** for runtime model calls, with subscription allowance
   recorded separately from charged cost.

## What `vsw` should not copy

- AntiFox source or prompt text. It is AGPL-3.0; this review is behavioural only.
- AntiFox's missing scope layer or fail-open traffic capture.
- Strix's full Kali tool fleet, its agent SDK, or its sandbox as a dependency.
  `vsw` keeps its own bounded deterministic pipeline and adds engines only as
  adapters.
- Any upstream prompt or skill text. Write `vsw` prompts from the contracts.

## Native slice

The first implementation slice does not need Docker or a live model:

- structured `Reproduction` and `ReproStep` models on `Finding`;
- `CoverageEntry` with provenance on `Coverage`;
- report rendering that prefers captured reproduction over prose, renders
  verbatim requests/responses in safely sized fences, and prints the coverage
  ledger;
- tests for fence breakout, coverage provenance, and step ordering.

The engine adapter contract, traffic recorder, and SARIF writer follow after the
native evidence model is stable. AntiFox remains the first adapter to integrate;
Strix remains the comparison engine.

## Licensing note

This document is a behavioural summary, not legal advice. Before distributing
`vsw` with an AntiFox adapter, review AGPL-3.0 obligations. Before reusing any
Strix code, preserve Apache-2.0 notices and check the terms of its skills,
prompts, and container image.
