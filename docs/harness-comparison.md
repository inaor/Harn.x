# Harness Comparison — DeepSeek DSH vs OpenHands

**Phase 2 strategic document.** Evidence from Phase 0 (`docs/deepseek-harness-architecture.md`) and Phase 2.0 (`docs/openhands-architecture.md`).

---

## Primitive mapping

| Primitive | DeepSeek DSH | OpenHands | Harn.x Mapping |
|---|---|---|---|
| Session | `ctx.sessions` / session log | `Conversation` + `ConversationState` | `session.started` / `session.ended` |
| Agent | `ctx.agents` / `agent/*` events | `Agent` on a Conversation | `agent.*` (+ `agent.id`) |
| Tool intent | `tools/pre-execute` exec object | `ActionEvent` (`tool_name`, `action`) | `tool.requested` |
| Pre-execution hook | Cordis `tools/pre-execute` waterfall | PreToolUse (`HookEventProcessor`) | Adapter → policy before allow |
| Result | `tools/result` / session tool events | `ObservationEvent` / PostToolUse | `tool.completed` / `tool.denied` |
| Context provenance | Message source + tool-result trust heuristics | Prompt sections, `<UNTRUSTED_CONTENT>`, UserPromptSubmit | Adapter emits `context.introduced` |
| Policy deny | `deny` decision from pre-execute | exit `2` / `decision:deny` → `UserRejectObservation` | Same `defaultRules` → block |
| Sub-agent | `ctx.subagents` / `subagent/start` | `DelegateExecutor` / task tools | Optional `subagent.*`; parent tool still hooked |
| Skill/plugin | Cordis plugins + `ctx.skills` | Skills (`invoke_skill`) + plugin hooks | Tool path maps; prompt inject is vendor-specific |
| Cancellation | `agent.cancel` | `CancellationToken` / pause / interrupt | Orthogonal; not a policy deny |
| Shell | `bash` / `pwsh` tools + `ctx.shell` seam | `terminal` tool + bash HTTP API | Adapter maps `terminal`→`bash`; API is blind spot |
| Sandbox | `ctx.sandbox` file-effect confinement | Workspace hosts agent-server container | Below-hook OS gap in both |

---

## COMMON HARNESS PRIMITIVES

These appear in both systems and are stable enough for Harn.x core:

1. **Session** — durable conversation/work identity  
2. **Agent** — actor identity (optionally nested)  
3. **Tool/action intent** — named capability + arguments before side effect  
4. **Pre-execution gate** — allow/deny before executor body  
5. **Observation/result** — success, error, or rejection visible to the model  
6. **Context introduction** — untrusted content can enter the loop (exact tagging differs)  
7. **Delegation** — parent can spawn child agents/tasks  
8. **Lifecycle hooks** — session start/end (and variants)

Harn.x core models these as normalized events + policy + graph — **not** as Cordis- or HookConfig-specific types.

---

## VENDOR-SPECIFIC PRIMITIVES

| Vendor | Primitive | Why not core |
|---|---|---|
| DeepSeek | Cordis `ctx.*` service seams (`shell`, `fs`, `subprocess`) | Plugin-tree specific; bypasses tool gate |
| DeepSeek | `tools/pre-execute` waterfall + guards | Cordis event name |
| DeepSeek | `dsh` profile / patch.yml composition | Packaging |
| OpenHands | Claude-compatible HookEvent / exit-code `2` contract | Hook runtime specific |
| OpenHands | `UserRejectObservation(rejection_source=…)` | Event class name |
| OpenHands | Confirmation policy + security_analyzer ensemble | Parallel control plane to hooks |
| OpenHands | Workspace provisioners (Docker/Cloud/API) | Infra, not agent intent |
| OpenHands | `/api/bash` + `/api/file` agent-server routes | Non-tool execution surfaces |
| OpenHands | Prompt/agent hook kinds + fail-open LLM hooks | Evaluation style |
| Both | Exact tool names (`bash` vs `terminal`) | Adapter synonym map |

---

## Portability stress notes

| Question | Evidence |
|---|---|
| Same policy both harnesses? | Yes — `defaultRules` unchanged; OpenHands maps `terminal`→`bash` |
| Schema change required? | No per-adapter edits — `export type HarnessName = string` |
| Core rewrite? | No |
| Denial before side effect? | Yes on ActionEvent / tools/pre-execute paths |
| Blind spots structurally similar? | Yes — direct capability seams (`ctx.shell` ↔ `execute_tool` / bash API) |

---

## Architectural picture

```text
DeepSeek Adapter (Cordis plugin) ──┐
                                   ├── Harn.x Core
OpenHands Adapter (PreToolUse CLI)─┘      ├── Recorder
                                          ├── Policy (shared rules)
                                          ├── Graph
                                          └── Detections
```
