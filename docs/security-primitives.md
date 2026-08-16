# HarnessSec Security Primitives

Classification of Phase 1 signals relative to existing security products.

```text
HARNESS_NATIVE  — only reconstructible from harness semantics
RUNTIME_GENERIC — already covered by EDR / eBPF / network / CNAPP
DERIVED         — inferred enrichment, not a native harness fact
UNKNOWN         — Phase 0 did not verify a reliable source
```

---

## Primitive catalog

| Primitive | Class | Source (Phase 0) | Why it matters |
|---|---|---|---|
| `session.started` / `session.ended` | HARNESS_NATIVE | `session/created`, `session/disposed` | Agent session identity |
| `agent.started` / `agent.ended` | HARNESS_NATIVE | `agent/created`, `agent/disposed` | Agent identity |
| `agent.step.admitted` | HARNESS_NATIVE | `agent/pre-step` enter | What the model was about to see |
| `agent.step.rejected` | HARNESS_NATIVE | `agent/pre-step` reject | Policy / admission deny at turn |
| `objective.captured` | DERIVED | first user `user/message` text | Best-effort objective; no dedicated objective API required for Phase 1 |
| `context.introduced` | HARNESS_NATIVE | `user/message` + `MessageSource` | Provenance from source kind |
| `context.trust` | DERIVED | policy over source kind / path | Metadata, not malware verdict |
| `tool.requested` | HARNESS_NATIVE | `tools/pre-execute` / `tool/call` | Intent **before** OS activity |
| `tool.completed` | HARNESS_NATIVE | `tools/result` / `tool/result` | Outcome as the model saw it |
| `tool.denied` | HARNESS_NATIVE | pre-execute deny / guard | Enforcement before body |
| `tool.blocked_post` | HARNESS_NATIVE | post-execute `block` | After body — weaker |
| `shell.command_requested` | HARNESS_NATIVE | bash tool args | Command string intent |
| `mcp.tool_requested` | HARNESS_NATIVE | tool name `mcp__*` | MCP selection + tool |
| `mcp.server_inferred` | DERIVED | parse `mcp__server__tool` | Server identity from naming |
| `skill.invoked` | HARNESS_NATIVE | `skill` tool / pre-step catalog | Skill lifecycle (partial) |
| `subagent.spawned` | HARNESS_NATIVE | `subagent/start` | Lineage edge |
| `subagent.ended` | HARNESS_NATIVE | `subagent/end` | Lineage close |
| `capability.available` | HARNESS_NATIVE | `tools/change` + registry snapshot | What agent *could* do |
| `capability.used` | HARNESS_NATIVE | successful tool request | What it *did* intend |
| `approval.asked` / `approval.decided` | HARNESS_NATIVE | approval audit events | Permission transition |
| `policy.decision` | HARNESS_NATIVE | HarnessSec engine | Our decision on a request |
| `policy.aftermath` | HARNESS_NATIVE | subsequent tool/step after deny | Post-block behavior |
| `process.exec` | RUNTIME_GENERIC | — | Out of scope |
| `file.read` (OS) | RUNTIME_GENERIC | — | Out of scope |
| `network.connect` | RUNTIME_GENERIC | — | Out of scope |
| `credential.access` | DERIVED | sensitive path/token in **tool args** | Not native `credentials.resolve` observe |
| `plugin.loaded` (peer) | UNKNOWN | no reliable admission hook | Partial at best; not Phase 1 detection dependency |

---

## Differentiator test

A primitive is worth owning if an EDR / proxy / identity product **cannot reliably reconstruct**:

1. **Which agent** intended the action
2. **Which user objective** it was serving
3. **Which context** influenced the decision (source + trust metadata)
4. **Which tool was selected before execution**
5. **Whether the harness blocked it before spawn**
6. **What the agent tried next after a block**
7. **Parent → child agent lineage** for the attempt

Passing examples for Phase 1:

- `tool.requested` with agent + session + frozen args + prior untrusted `context.introduced`
- `tool.denied` before bash body → no OS process for that command
- `subagent.spawned` with parent_agent_id
- `policy.aftermath` alternate tool after deny

Failing / out-of-scope examples:

- “process X opened `~/.ssh/id_rsa`” (EDR)
- “TCP connect to 1.2.3.4” (network)
- Claiming `file.read` from `bash -c cat …` (not harness-native)

---

## Phase 1 rule primitives (allowed)

Rules may only combine:

```text
HARNESS_NATIVE + DERIVED(from harness facts)
```

They must not require `RUNTIME_GENERIC` telemetry.
