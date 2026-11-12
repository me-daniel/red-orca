# Red Orca Pod

**An open, model-agnostic cyber agent for red teams — built so you don't need access to Mythos or any other closed cyber model to defend against the threats that use them.**

---

## The problem

The strongest cyber-capable models are closed. Access to systems like Mythos is gated behind contracts, budgets, and approval processes that most defenders, researchers, small security teams, and independent red teams will never clear. Meanwhile, the same class of capability is being assembled by attackers from whatever they can reach: a closed frontier model for planning, an open-weights model for payload work, another for analysis, a third for persistence and evasion.

The result is an asymmetry that has nothing to do with skill. A defender with deep expertise and no model access is outgunned by an attacker with shallow expertise and a credit card.

That asymmetry is the thing this project exists to break.

## The idea

**The Red Orca Pod** combines many models — open weights and closed source — into a single cyber agent that is stronger than any one of its parts.

Orcas don't hunt alone. A pod coordinates: one drives, others flank, another calls, and the group takes down prey far larger than any individual. This project applies the same principle to models. Instead of betting everything on one vendor's cyber model, the Pod routes each task to the model that is actually best at it, runs independent models in parallel, cross-checks their output, and synthesizes a single result.

A closed model may be the best planner. An open-weights model may be the best at code transformation, at parsing noisy telemetry, at writing a detection rule, at reasoning over a huge local corpus without data leaving the building. The Pod doesn't care. It treats every model as a specialist and composes them.

**The core requirement: the Pod must be fully useful with open-weights models alone.** Closed models are an optional upgrade, never a dependency. If you can run a model locally, you can run the Pod.

## What "superior" means here

Not "beats every closed model at everything." That's not a credible claim, and it isn't the goal.

Superior means:

- **Better than any single model available to you**, including the closed one you can't afford.
- **Better than a single open-weights model**, because specialization and cross-checking beat a generalist working alone.
- **Better than an attacker's ad-hoc stack**, because the Pod is coordinated, auditable, and repeatable instead of a pile of prompts in a chat window.

Ensembles, routing, and verification are not new ideas. Applying them deliberately to offensive and defensive cyber work, with open weights as the floor rather than the fallback, is the point.

## How it works

```
                    ┌─────────────────────┐
                    │      Orchestrator   │
                    │  plans, routes,     │
                    │  decomposes tasks   │
                    └──────────┬──────────┘
                               │
        ┌──────────────┬───────┴───────┬──────────────┐
        │              │               │              │
   ┌────▼────┐   ┌─────▼─────┐   ┌─────▼─────┐  ┌─────▼─────┐
   │Recon &  │   │Exploitation│  │Analysis & │  │Detection &│
   │OSINT    │   │& Payload   │  │Triage     │  │Response   │
   └────┬────┘   └─────┬─────┘   └─────┬─────┘  └─────┬─────┘
        │              │               │              │
        └──────────────┴───────┬───────┴──────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Verifier / Judge  │
                    │  cross-model review │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Final synthesis    │
                    └─────────────────────┘
```

1. **Plan** — the orchestrator decomposes the objective into subtasks and assigns each one a capability profile, not a model name.
2. **Route** — a routing layer maps capability profiles to whatever models are configured: local, remote, open weights, closed, cheap, expensive.
3. **Run the pod** — multiple models can work the same subtask in parallel, especially where being wrong is expensive.
4. **Verify** — a separate model (ideally from a different family) reviews output for correctness, hallucination, and unsafe assumptions.
5. **Synthesize** — results are merged into one coherent product: a finding, a report, a detection, a fix.

Because routing is by capability and not by vendor, swapping in a new open-weights model is a config change, not a rewrite. A new closed model is just another optional endpoint.

## Design principles

- **Open weights are the floor, not the fallback.** Every workflow must work without a single closed API key.
- **Model-agnostic by construction.** No vendor SDK is load-bearing. Adapters are thin and replaceable.
- **Local-first.** Data you can't send to a vendor stays on your hardware, processed by models you control.
- **Cross-check by default.** One model's confident answer is a hypothesis. Two independent models agreeing is evidence.
- **Auditable.** Every task records which model produced which output, so results can be reviewed, reproduced, and defended.
- **Honest about limits.** The Pod reports uncertainty and disagreement instead of smoothing it away.
- **Authorized use only.** See below.

## Getting started

> The implementation is in progress. This section will fill in as components land.

```bash
git clone https://github.com/me-daniel/red-orca.git
cd red-orca

# Configure model endpoints and keys. Never commit this file.
cp .env.example .env   # or create .env by hand
```

Your `.env` holds API keys and endpoint URLs for any closed models you choose to add. The Pod runs with open-weights endpoints only; closed providers are optional.

Set `OPENCODE_API_KEY` for the OpenCode Go routes, or `OPENROUTER_API_KEY` for
OpenRouter. `vsw` loads `.env` at startup. Runtime routes stay disabled until
each one is checked and evaluated; `vsw models list` shows the state without
printing secret values.

`.env` is gitignored. Agent scratch files, private notes, local model weights, and anything else that shouldn't be public are gitignored too.

## Roadmap

- [ ] Model adapter layer (OpenAI-compatible, local runtimes, vendor-specific)
- [ ] Capability-based router
- [ ] Orchestrator with task decomposition
- [ ] Parallel pod execution and cross-model verification
- [ ] Reference workflows: recon, exploitation, detection engineering, incident triage
- [ ] Local-only profile that needs no external API
- [ ] Evaluation harness for comparing pods and single models
- [ ] Run logs and reproducible reports

## Implementation: `vsw`

The Pod is implemented as the **Vorsprung Security Workbench (`vsw`)**, a bounded, evidence-first security testing tool. Requirements live in `OPENCODE_BUILD_BRIEF.md`; build routing lives in `MODEL_ROUTING.md`; assessment routing lives in `RED_MODEL_ROUTING.md`.

```bash
uv sync --all-extras
uv run vsw doctor       # toolchain, config, skills, routing policy
uv run vsw demo         # deterministic mock demo, no credentials
uv run vsw smoke        # mock coding-and-review task
uv run vsw smoke --live # Claude Opus Medium advises, Codex Sol High implements and reviews
uv run vsw policy       # build allowlist and cyber-only exclusions
uv run vsw models list  # runtime routes, disabled state, key presence
uv run vsw models check <route>  # one live call; the route stays disabled
```

Stage: **M1 local HTTP observation**. `vsw lab up`, `vsw run`, and `vsw report` inspect
a local fixture, capture hashed evidence, and produce a report; the clean control
produces no findings. Scope is enforced per request against pinned addresses, and
HTTPS is refused rather than tunnelled, so this stage is local HTTP only. Each
observation run writes `report.md`, `findings.json` (the CLI's full run payload),
`coverage.json`, `exchanges.json` (a metadata index linked to evidence IDs), and
`run.json`. Failed evidence integrity makes the run fail and withholds validated
finding labels and coverage claims. `PROGRESS.md` records what is live, mocked,
and blocked. The build coordinator is DeepSeek V4.1 Flash via OpenCode. Claude and
Codex are bounded delegates through a policy-checked gateway; cyber-only models
are rejected during build. The runtime `ModelGateway` is wired for OpenCode Go and
OpenRouter, but every route is disabled until it is checked and evaluated. None
of this is a live assessment.

## Who this is for

- Defenders who need to model attacker capability they can't buy access to.
- Red teams without a frontier-model budget.
- Security researchers who want to study multi-model cyber behavior.
- Anyone who believes capability shouldn't be gated behind a contract.

## Authorized use

This project is for **authorized security testing, defensive research, and education**. Use it only against systems you own or have explicit written permission to test. Nothing here is a license to attack. If you're not sure whether you're authorized, you aren't.

The goal is to close a capability gap for defenders, not to hand attackers a better toolkit. Build accordingly.

## Contributing

Contributions are welcome: new model adapters, routing strategies, verification prompts, workflows, and evaluations. Please keep the open-weights-only path working — a change that makes a closed model mandatory will not be merged.

## License

TBD.
