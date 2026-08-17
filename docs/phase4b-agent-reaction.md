# Phase 4B — AGENT_REACTION

**Status:** Implemented (first PR)  
**Phase:** Behavioral Runtime Correlation  

## What this is

`agent.reaction` is a **factual** classification of observable agent behavior
after a Harn.x `policy.decision` BLOCK.

It is **not**:

- a response / remediation engine  
- a security detection  
- a `caused_by` claim  

Security interpretation remains `behavior.detection` with unchanged Phase 3 bars.

```text
reaction.type = ALTERNATE_TOOL
        ≠
behavior.detection = agent.policy_circumvention
```

## Taxonomy

| Type | Rule |
|------|------|
| `STOP` | OBSERVED `session.ended` / `agent.ended` (or structured stop signal); no tools in window |
| `ASK_USER` | OBSERVED `approval.asked` (or structured ask signal); no tools in window |
| `RETRY_SAME` | Same capability family + exact/strong equivalent action/target |
| `ALTERNATE_TOOL` | **Different** family **and** exact/strong equivalent action/target |
| `DELEGATE` | Same-session OBSERVED `subagent.spawned` |
| `UNKNOWN` | Missing telemetry, silence without ask/stop, or non-equivalent next tool |

**Silence alone is never ASK_USER or STOP.**

## Window

```text
DEFAULT_REACTION_WINDOW_MS = 120_000
```

Configurable via correlator options. **Not** the 30s circumvention detector window.

## ALTERNATE_TOOL examples

| Sequence | Reaction |
|----------|----------|
| Read `.env` → Grep `.env` | `ALTERNATE_TOOL` |
| Read `.env` → `pytest` | `UNKNOWN` |

## CLI

```text
harnesssec why <session-id|event-id>
```

Answers: what was blocked, why, what next (reaction), security-relevant? (joined detections only), evidence.

## Per-harness support (honest)

See `REACTION_HARNESS_SUPPORT` in `src/behavior/reaction.ts`.

| Harness | ASK_USER / STOP |
|---------|-----------------|
| Cursor | PARTIAL — no reliable ask/stop hooks; expect `UNKNOWN` often |
| DeepSeek DSH | Use structured signals when present |
| OpenHands | UNKNOWN unless structured ask/end recorded |

Transcript prose is **not** authoritative.

## Out of scope (this PR)

Dashboard, DSL, SOAR, Harness #4, TOOL_RESULT, DSH result control,
lineage productization, response engine, new behavioral detectors.
