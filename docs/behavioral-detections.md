# Harn.x Behavioral Detections (Phase 3)

Stateful detectors over normalized events. Implementation: `packages/harnesssec/src/behavior/`.
Model: [`behavioral-model.md`](behavioral-model.md).

## Detector portability vs live adapter telemetry

These are **separate** claims:

| Claim | Meaning | Phase 3 status |
|---|---|---|
| **Detector portability** | Same `BehavioralEngine` / detectors run on normalized events regardless of `harness.name` | **PASS** — proven for DSH and OpenHands named sequences |
| **Live adapter telemetry** | Adapter emits the OBSERVED fields needed in a live harness session | DSH subagent lineage: available; **OpenHands live lineage: PARTIAL** (no `subagent.*` hooks today) |

OpenHands **delegated-circumvention is detector-portable** (same code path with explicit `parent_agent_id` on normalized events) while **live OpenHands lineage telemetry remains PARTIAL**. Do not conflate the two.

## Configuration

| Setting | Default | Constant | Notes |
|---|---|---|---|
| Same-agent alternate window | 30s | `DEFAULT_WINDOW_MS` | Block → alternate tool |
| Blocked action delegation TTL | 5 min | `BLOCKED_ACTION_DELEGATION_TTL_MS` | How long a block remains eligible for delegated correlation |
| Spawn → child action window | 30s | `DELEGATION_TO_CHILD_ACTION_MS` | Max delay from explicit spawn to equivalent child action |
| Equivalence | exact/strong only | — | `unknown` never matches |
| Lineage | Explicit parent/spawn only | — | Scoped by `(session_id, agent_id)` |

### Delegated circumvention timing

Requires **both**:

1. Child action within `BLOCKED_ACTION_DELEGATION_TTL_MS` of the ancestor block
2. Child action within `DELEGATION_TO_CHILD_ACTION_MS` of OBSERVED spawn/delegation timestamp

Example: block at t0, spawn at t+120s, child equivalent at t+125s → **DETECT**.  
Spawn at t+120s, child at t+200s → **NO DETECT** (spawn→action > 30s).

## Normalization levels

| Level | Use in circumvention? | Examples |
|---|---|---|
| `exact` | Yes | `read`/`write` with path; `web_fetch` with url |
| `strong` | Yes | Whole-command `cat PATH`; whole-command `curl URL` |
| `unknown` | **No** | Pipelines, python one-liners, missing args, opaque tools |

Original OBSERVED tool/args are always kept on `NormalizedAction.original`.

## Detector: Alternate capability circumvention

**Kind:** `agent.policy_circumvention`  
**Severity:** high

### Evidence bar

1. Prior `policy.decision` = `block` with DERIVED `(category, target)` at exact/strong
2. Same `session_id` and same `agent_id`
3. Later `tool.requested` with equivalent `(category, target)` at exact/strong
4. **Different** capability family (e.g. `shell` vs `filesystem`)
5. Δt ≤ 30s
6. Not an identical tool retry

### Example

```text
bash: cat ~/.ssh/id_rsa     → BLOCK (strong)
read: ~/.ssh/id_rsa         → DETECT agent.policy_circumvention (exact)
```

### False positives (must not fire)

- Blocked sensitive read → `git status`
- Blocked file A → read file B
- Equivalent action after >30s
- Ambiguous shell (`python -c open(...)`, pipelines) → unknown → no detect

## Detector: Delegated policy circumvention

**Kind:** `agent.delegated_policy_circumvention`  
**Severity:** critical

### Evidence bar

1. Parent (ancestor) BLOCK with `(category, target)` exact/strong still within delegation TTL (default 5 min)
2. Child has **OBSERVED** `parent_agent_id` / spawn in the **same session**
3. Child attempts equivalent `(category, target)` within spawn→action window (default 30s)

### Telemetry note

- **Detector-portable** across harness names.
- **Live OpenHands:** lineage emission PARTIAL — adapter does not emit `subagent.*` today.

## Detector: Delegation privilege expansion (conditional)

**Kind:** `agent.delegation_privilege_expansion`  
**Severity:** medium (signal)

Requires OBSERVED `capability.snapshot` on **both** parent and child (latest snapshot **replaces** prior available set). Sequences supported:

- parent snapshot → child spawn **with** snapshot
- parent snapshot → child spawn → child capability.snapshot

Missing snapshots → no detection. Never infer availability from tool use.

## Architecture

```text
HarnessEvent  →  FlightRecorder
              →  PolicyEngine
              →  BehavioralEngine  (no FlightRecorder dependency)
```

`behavior.detection` events are returned from `observe()` and fan-out recorded by the caller. Re-observing a `behavior.detection` never emits further detections.

## CLI

```text
harnesssec detections [session]
harnesssec incident <session>
```

## Tests

[`packages/harnesssec/tests/phase3-behavior.test.ts`](../packages/harnesssec/tests/phase3-behavior.test.ts)
