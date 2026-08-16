# Cursor Coverage Matrix (Phase 4A)

Values reflect **documented Cursor exposure** + **Harn.x adapter intent**.
Live IDE verification may upgrade UNKNOWN → PASS/PARTIAL/FAIL in `phase4a-cursor-alpha.md`.

| Primitive | Cursor exposes | Harn.x maps | Pre-exec | Blockable | Notes |
|---|---|---|---|---|---|
| Session | `conversation_id` / `session_id` on session hooks | `session.started` / `session.ended` | N/A | N | sessionStart is fire-and-forget |
| Prompt/context | `beforeSubmitPrompt` prompt + attachments | `context.introduced` when untrusted markers | Y | Prompt submit only | Not full provenance graph |
| Shell | `beforeShellExecution` / `afterShellExecution` | `tool.requested` + `shell.command_requested` | Y | **Y (deny)** | **Canonical enforcement proof** |
| File read | `beforeReadFile` | `tool.requested` (Read); path/hash only | Y | Y (deny) | Existing policy rarely blocks Read alone; content not persisted |
| File write | `afterFileEdit` (after) | observe edit metadata | N | N | Pre-write gate via `preToolUse` Write if used |
| MCP | `beforeMCPExecution` / `afterMCPExecution` | `mcp.tool_requested` + trust | Y | Y (deny) | PARTIAL until live proof |
| Agent identity | model slug/id only | opaque `raw` metadata | — | — | No stable Cursor agent UUID in common schema |
| Subagent | `subagentStart` / `subagentStop` | `subagent.spawned` / ended when fields exist | Y observe | **Observation-only** | No block claim without side-effect proof |
| Delegation | Task tool / subagent fields | PARTIAL | PARTIAL | U | Do not fabricate lineage |
| Capabilities | Not a first-class Cursor snapshot | PARTIAL via tools used | N | N | No fake capability.snapshot |

## Status legend for `harnesssec status`

Every checkmark must match this matrix — no aspirational greens.
