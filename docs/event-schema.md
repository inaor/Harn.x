# Event Schema

Normalized HarnessSec events for Phase 1.

Only fields that Phase 0 can populate are required.
Missing data stays missing — never fabricated.

Full TypeScript source: `packages/harnesssec/src/events/schema.ts`

---

## Envelope

```json
{
  "id": "evt_…",
  "timestamp": "2026-08-16T00:00:00.000Z",
  "event_type": "tool.requested",
  "harness": { "name": "deepseek-dsh", "version": "optional" },
  "session": { "id": "…" },
  "agent": { "id": "…", "parent_agent_id": null },
  "objective": { "id": "…", "description": "…" },
  "context": {
    "id": "…",
    "source_type": "user|plugin|tool_result|repository_file|website|…",
    "source": "…",
    "trust": "trusted|untrusted|unknown",
    "excerpt": "…"
  },
  "action": { "type": "…", "target": "…", "arguments": {} },
  "tool": {
    "name": "…",
    "provider": "native|mcp|…",
    "call_id": "…",
    "sensitivity": "low|medium|high"
  },
  "capability": { "available": ["…"], "used": "…" },
  "policy": {
    "decision": "allow|alert|block|terminate",
    "rule": "…",
    "severity": "…",
    "reason": "…"
  },
  "links": {
    "caused_by": "evt_…",
    "parent_event": "evt_…",
    "parent_agent": "agent-…",
    "delegated_by": "agent-…",
    "context_source": "evt_…",
    "tool_source": "evt_…",
    "result_of": "evt_…",
    "policy_decision_for": "evt_…"
  },
  "raw": { "source_hook": "tools/pre-execute", "notes": "…" }
}
```

---

## Event types (Phase 1)

| event_type | Source hook | Notes |
|---|---|---|
| `session.started` / `ended` | `session/created` / `disposed` | |
| `agent.started` / `ended` | `agent/created` / `disposed` | |
| `objective.captured` | DERIVED from first user message | Best-effort |
| `context.introduced` | `user/message` or untrusted `tool/result` | Trust from `MessageSource` / tool class |
| `tool.requested` | `tools/pre-execute` | Intent before body |
| `shell.command_requested` | bash/pwsh args | Command string only |
| `mcp.tool_requested` | `mcp__*` tool name | |
| `tool.completed` | `tools/result` | |
| `tool.denied` | pre-execute deny path | Body did not run |
| `capability.snapshot` | `tools.schemas()` at agent create | Available |
| `capability.used` | implied via tool.requested | |
| `subagent.spawned` / `ended` | `subagent/start` / `end` | In-process |
| `policy.decision` | HarnessSec engine | |
| `policy.aftermath` | next tool after BLOCK | Post-block behavior |

---

## Explicitly absent

```text
file.read          — not a harness event (DERIVED from args only)
network.connect    — not a harness event
process.exec       — not observable via tools/*
```
