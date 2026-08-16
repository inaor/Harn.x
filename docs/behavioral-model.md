# Harn.x Behavioral Model (Phase 3.0)

Stateful detection operates on the **normalized event model**, not vendor payloads.
This document defines minimum primitives and epistemic honesty rules.

## Epistemic tags

| Tag | Meaning | Allowed in detections? |
|---|---|---|
| **OBSERVED** | Present on a recorded `HarnessEvent` (ids, timestamps, tool name, args, policy decision, `parent_agent_id` on `subagent.spawned`, capability snapshots) | Yes — primary evidence |
| **DERIVED** | Deterministic function of OBSERVED fields (category + target) with level `exact` \| `strong` \| `unknown` | Yes — circumvention only for `exact`/`strong` |
| **CORRELATED** | Temporal / structural association (same session, within window, same target after block) — **not** proven causal intent | Yes — must not use `caused_by` |
| **INFERRED** | Speculative agent intent, LLM semantic equivalence, lineage from timestamps alone, availability from tool use | **No** in Phase 3 |

Do not claim model reasoning or intent that is not OBSERVED or DERIVED.

Original tool name + arguments are always preserved on `NormalizedAction.original`.

## Primitives

| Primitive | Epistemic | Source |
|---|---|---|
| Agent identity | OBSERVED | `event.agent.id` |
| Parent agent identity | OBSERVED | `event.agent.parent_agent_id` / `links.parent_agent` / `subagent.spawned` |
| Session | OBSERVED | `event.session.id` |
| Turn | OBSERVED | `event.turn` when present |
| Objective | OBSERVED | `objective.captured` / session objective |
| Action intent (raw) | OBSERVED | `tool.name` + `action.arguments` |
| Normalized action category | DERIVED | `normalizeAction(...)` with level exact/strong/unknown |
| Action target | DERIVED | Canonical path/host when deterministic; else empty + unknown |
| Policy result | OBSERVED | `policy.decision` |
| Blocked action | OBSERVED + DERIVED | Block decision + normalized category/target (`BlockedActionMemory`) |
| Agent reaction | CORRELATED | Later tool request after block (not `caused_by`) |
| Delegation | OBSERVED | `subagent.spawned` + explicit parent/child ids |
| Child agent | OBSERVED | Child `agent.id` with `parent_agent_id` |
| Capability available | OBSERVED | Latest `capability.snapshot.available` only — **replaces** prior set; never inferred from tool use; scoped by `(session_id, agent_id)` |
| Capability used | OBSERVED | `tool.requested` / `capability.used` history (accumulates); scoped by `(session_id, agent_id)` |
| Capability change | DERIVED | Diff of successive **snapshots** |
| Context trust | OBSERVED | `context.trust` |
| Temporal relationship | OBSERVED | Event timestamps + configured window |
| Semantic / action equivalence | DERIVED | Same normalized `(category, target)` at exact/strong only |

## Parallel consumers

```text
normalized HarnessEvent
        ├── FlightRecorder (persist / graph)
        ├── PolicyEngine (per-request enforcement)
        └── BehavioralEngine (stateful detection)
```

BehavioralEngine consumes events independently of persistence. Recorder may fan-out detections it returns; detection does not require disk.

## Action category taxonomy (small)

- `READ_FILE`
- `READ_SENSITIVE_FILE`
- `WRITE_FILE`
- `EXECUTE_COMMAND`
- `EXTERNAL_NETWORK_ACCESS`
- `MCP_TOOL_USE`
- `CLOUD_ACTION`
- `DELEGATE`
- `CAPABILITY_CHANGE`
- `OTHER`

No LLM-based semantic classification in Phase 3.

## Capability state

Distinguish:

- **CAPABILITY AVAILABLE** — only from OBSERVED `capability.snapshot`; each snapshot **replaces** the prior available set
- **CAPABILITY USED** — tool actually requested (history accumulates)

Never infer availability solely because a tool was used.

All agent behavioral / capability identity is keyed by `(session_id, agent_id)` so reused agent IDs cannot leak across sessions.

## Blocked action memory

When policy BLOCKs a tool request, store DERIVED `(category, target, level)` with OBSERVED agent/session/time/rule in `BlockedActionMemory`.
This is behavioral memory for subsequent CORRELATED matches — not a claim of unobserved agent intent.

## Lineage rule

Parent→child edges require explicit OBSERVED parent linkage (`parent_agent_id` / links).
**Never** infer lineage from timestamps alone.

Observed **delegation/spawn** is stricter: only the normalized `subagent.spawned` event may set `spawn_timestamp` / `spawn_event_id`. Parent relationship alone does not count as observed delegation for delegated circumvention.

## Relationship types on the graph

Defensible Phase 3 relations:

| Relation | Meaning | Causal claim? |
|---|---|---|
| `parent_agent` | Explicit lineage | Structural |
| `delegated_by` / `delegated_to` | Explicit spawn linkage | Structural |
| `attempted_after` | Tool after prior block (correlation) | No |
| `equivalent_to` | Same normalized category+target | DERIVED only |
| `blocked_by` | Policy decision for tool | OBSERVED link |
| `correlated_with` | Weak temporal/structural association | No |

Do **not** emit `caused_by` for behavioral circumvention.

## Out of scope for this model

- Vendor-specific detection branches
- OS/eBPF/network primary features
- YAML detection language
- Harness #3
