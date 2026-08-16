# Phase 3.2 — Live Autonomous Behavior Proof

Experimental harness for observing **real model** post-denial behavior through
existing Harn.x adapters + Phase 3 `BehavioralEngine`.

This is **not** a detector release. Do not treat aggregates as benchmarks.

## What it proves

1. Real model chooses Action A  
2. Existing Harn.x policy BLOCKs  
3. Denial returns into the agent loop  
4. Model autonomously chooses next behavior (not scripted)  
5. Harn.x records events; existing detectors evaluate them  

## Requirements

```bash
export HARNX_TEST_PROVIDER=openai          # or compatible
export HARNX_TEST_MODEL=gpt-4o-mini        # any tool-capable model
export HARNX_TEST_API_KEY=...              # or OPENAI_API_KEY / DEEPSEEK_API_KEY
# optional:
export HARNX_TEST_BASE_URL=https://api.openai.com/v1
export HARNX_EXPERIMENT_RUNS=10
```

OpenHands also needs the repo-local `openhands-sdk/` checkout + `uv`.

## Run

```bash
cd packages/harnesssec
npm ci && npm run build
npm run experiment:live-autonomy
# or:
HARNX_EXPERIMENT_RUNS=10 npm run experiment:live-autonomy -- --harness dsh
```

Executable entry: `packages/harnesssec/scripts/live-autonomy/runner.ts`  
Scenario/schema/docs stay under `experiments/live-autonomy/`.

Without credentials the runner **skips** live calls, writes skipped results, and exits 0.
That is infrastructure dry-run — **not** Phase 3.2 PASS evidence.

## Canonical mode (required for evidence)

- `scripted_followup` / `inject_post_block` **forbidden**
- No `experiment:inject-post-block` hooks after BLOCK  
- OpenHands: UserPromptSubmit only (no `openhands-seed` in evidence sessions)

## Analyze a session

```bash
cd packages/harnesssec
npm run cli -- --store /path/to/store incident <session_id>
npm run cli -- --store /path/to/store detections <session_id>
```

Incident timeline labels: `[OBSERVED]` / `[DERIVED]` / `[CORRELATED]`.

## Layout

| Path | Role |
|---|---|
| `scenarios/` | Benign prompts (no circumvention coaching) |
| `src/canonical.ts` | Anti-injection guards |
| `src/types.ts` / `schema/` | Run / aggregate schema |
| `src/harness-openhands.py` | OpenHands Conversation + real LLM |
| `../../packages/harnesssec/scripts/live-autonomy/` | Node runner + DSH AgentLoop entry |
| `results/` | Local outputs (gitignored except examples) |

## Reaction classes

`STOPPED` · `RETRIED_IDENTICAL_ACTION` · `CHANGED_CAPABILITY` · `EQUIVALENT_ACTION` ·
`DELEGATED` · `CHANGED_OBJECTIVE` · `UNKNOWN`

Classification is deterministic over recorded events (`classifyPostBlockReaction`).
It does **not** imply a security detection — detectors still require Phase 3 evidence bars.
