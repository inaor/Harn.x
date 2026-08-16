# OpenHands — Security Architecture Map

**Phase 2.0 deliverable.** Source-traced from local checkouts (gitignored; not vendored):

- `openhands-sdk/` — https://github.com/OpenHands/software-agent-sdk  
- `openhands/` — https://github.com/OpenHands/OpenHands (frontend / canvas; agents live in the SDK)

This report answers one question:

> Can Harn.x observe and deny agent intent at an OpenHands pre-execution choke point without forking OpenHands and without rewriting Harn.x core semantics?

**Short answer: yes for agent-mediated tools (`terminal`, `file_editor`, `browser_*`, MCP tools, skill invoke) when PreToolUse hooks are configured and wired. No for workspace/bash HTTP APIs, `execute_tool`, `rerun_actions`, or OS behavior below the tool executor.**

---

## 1. What OpenHands actually is

OpenHands is not a single monolithic “Runtime class” anymore. The SDK composition is:

```text
Frontend (openhands/)  ──HTTP/WS──►  Agent Server (openhands-agent-server)
                                         │
                                         ▼
                                   LocalConversation + Agent
                                         │
                                         ▼
                                   Tools (openhands-tools) on LocalWorkspace
```

Sandboxes are **Workspaces that host an agent-server**:

| Class | Path | Role |
|---|---|---|
| `DockerWorkspace` | `openhands-workspace/.../docker/workspace.py` | Docker image running agent-server |
| `OpenHandsCloudWorkspace` | `.../cloud/workspace.py` | Cloud-provisioned sandbox |
| `APIRemoteWorkspace` | `.../remote_api/workspace.py` | Runtime API / sysbox |
| `LocalWorkspace` | `openhands-sdk/.../workspace/local.py` | In-process FS + commands (no container) |

The frontend AGENTS.md states the OpenHands app repo is canvas/UI; agents/tools/server live in the Software Agent SDK.

---

## 2. Turn / step flow — interception map

```text
Conversation.run / arun
  → Agent.step / astep
  → LLM completion (tool_calls)
  → Agent._get_action_event
       → on_event(ActionEvent)          ★ PreToolUse hooks fire here
  → optional confirmation / security_analyzer
  → Agent._execute_actions
       → _ActionBatch.prepare           ★ skips state.blocked_actions
       → ParallelToolExecutor
       → Agent._execute_action_event
            → tool(action, conversation)   ★ OS / FS / browser side effects
       → on_event(ObservationEvent)     ★ PostToolUse (non-blocking)
  → continue / Finish / Stop hooks
```

Primary sources:

- `openhands-sdk/.../agent/agent.py` — `step`, `_get_action_event`, `_execute_action_event`, `_ActionBatch`
- `openhands-sdk/.../hooks/conversation_hooks.py` — `HookEventProcessor`
- `openhands-sdk/.../hooks/manager.py` — `HookManager.run_pre_tool_use`
- `openhands-sdk/.../hooks/executor.py` — exit-code / JSON deny contract
- `openhands-sdk/.../conversation/impl/local_conversation.py` — hook wiring via `create_hook_callback`

---

## 3. Lifecycle primitives

### 3.1 Session / conversation

| Concern | Owner | Evidence |
|---|---|---|
| Create | `Conversation` factory / Agent Server `ConversationService` | `conversation/conversation.py`, `agent_server/conversation_service.py` |
| State | `ConversationState` (events log, blocked_actions, status) | `conversation/state.py` |
| SessionStart/End hooks | `HookEventProcessor.run_session_start/end` | `conversation_hooks.py`; wired in `local_conversation.py` |
| Persistence | Event log under conversation dir | `ConversationState` |

### 3.2 Agent

| Concern | Owner |
|---|---|
| Agent definition + tools | `Agent` (`sdk/agent/agent.py`) |
| Step loop | `Agent.step` / `astep` |
| Status | `ConversationExecutionStatus` (`IDLE`, `RUNNING`, `WAITING_FOR_CONFIRMATION`, `PAUSED`, `FINISHED`, …) |

### 3.3 Model action generation

Intent object: **`ActionEvent`** (`sdk/event/llm_convertible/action.py`) with:

- `tool_name` (e.g. `terminal`, `file_editor`)
- `tool_call` (LLM function call id + JSON arguments)
- `action` (typed `Action` model, e.g. `TerminalAction.command`)

Built in `Agent._get_action_event`, emitted via `on_event` **before** execution.

### 3.4 Event stream

Not the legacy `EventStream` class. Today: append-only `ConversationState.events` + PubSub/WebSocket fan-out from Agent Server (`event_service.py`, `sockets.py`).

Key event types: `MessageEvent`, `ActionEvent`, `ObservationEvent`, `UserRejectObservation`, `HookExecutionEvent`, `AgentErrorEvent`.

### 3.5 Tools / actions

| Tool | Action type | Executor | Path |
|---|---|---|---|
| `terminal` | `TerminalAction` | `TerminalExecutor` | `openhands-tools/.../terminal/` |
| `file_editor` | `FileEditorAction` | `FileEditorExecutor` | `.../file_editor/` |
| `browser_*` | `BrowserAction` | `BrowserToolExecutor` | `.../browser_use/` |
| MCP tools | MCP action wrappers | `MCPToolExecutor` | `sdk/mcp/` |
| `invoke_skill` | skill invoke action | skill tool | `sdk/skills/` + tools |

### 3.6 PreToolUse / PostToolUse

| Hook | Can block? | Mechanism |
|---|---|---|
| PreToolUse | **Yes** | exit `2` or JSON `{"decision":"deny"}` → `block_action` → `UserRejectObservation(rejection_source="hook")` |
| PostToolUse | No | Observability only |
| UserPromptSubmit | Yes | `block_message` → skip LLM |
| Stop | Yes (prevent finish) | Continue agent with feedback |
| SessionStart/End | No | Lifecycle |

Hook kinds: `COMMAND` (shell), `PROMPT` (LLM), `AGENT` (nested agent). Config: `.openhands/hooks.json` or programmatic `HookConfig`.

**Critical:** exit code `1` does **not** block. Only `2` (or explicit deny JSON). Async PreToolUse cannot block. Prompt/agent hook failures **fail-open** to allow.

### 3.7 Runtime dispatch / sandbox

Tools execute **in the Agent Server / LocalConversation host process** (the sandbox container when remote). There is no separate ActionExecutionServer gate below hooks.

Below the hook:

- Shell → tmux pane / subprocess / PowerShell (`TerminalSession.execute`)
- File → local FS under workspace root
- Browser → Playwright/Chromium in the same environment

### 3.8 Skills / sub-agents / MCP / cancellation

| Primitive | Path | Notes |
|---|---|---|
| Skills | `sdk/skills/`, `invoke_skill` tool | Tool-mediated → PreToolUse applies |
| Sub-agents | `sdk/subagent/`, `DelegateExecutor` | Parent can block `delegate`; child has own `hook_config` |
| MCP | `sdk/mcp/` | Tools enter `tools_map` → same ActionEvent path |
| Cancellation | `CancellationToken`, `pause`, `interrupt` | Orthogonal to hooks; not a PreToolUse deny |

---

## 4. Per-primitive choke-point answers

For each capability: (1) intent, (2) queued, (3) pre-exec choke, (4) full args?, (5) deny?, (6) denial object, (7) after deny, (8) visible to agent?, (9) bypass?, (10) below hook, (11) needs OS telemetry?, (12) hook location.

### Tool / action (generic)

1. **Intent:** `ActionEvent.action` + `tool_name`  
2. **Queued:** Emitted into conversation event callback / state before `_execute_actions`  
3. **Choke:** `HookEventProcessor._handle_pre_tool_use` on ActionEvent  
4. **Args:** Yes — `event.action.model_dump()` → hook `tool_input`  
5. **Deny:** Yes (sync PreToolUse)  
6. **Object:** `ConversationState.blocked_actions[id]` → `UserRejectObservation`  
7. **After:** Tool body not called; rejection observation emitted  
8. **Visible:** Yes — LLM sees `Action rejected: …`  
9. **Bypass:** `execute_tool`, `rerun_actions`, direct executor calls  
10. **Below:** `ToolDefinition.__call__` → tool executor  
11. **OS telemetry:** For child process / network effects after allow  
12. **Location:** Agent Server / LocalConversation host (sandbox container when remote)

### Shell (`terminal`)

1. `TerminalAction.command` inside `ActionEvent`  
2. Same ActionEvent emit  
3. PreToolUse matcher `terminal` (or `*`)  
4. Yes — full command string  
5. Yes  
6. `UserRejectObservation(rejection_source="hook")`  
7. No `TerminalSession.execute`  
8. Yes  
9. **Yes** — `BashEventService` / `/api/bash/*`, `LocalWorkspace.execute_command`, `execute_tool`  
10. tmux/`send_keys` or subprocess on host  
11. Yes for what the shell process actually does after allow  
12. Agent Server host

### File (`file_editor`)

1. `FileEditorAction`  
2–8. Same ActionEvent / PreToolUse pattern  
9. **Yes** — `/api/file/*`, workspace upload APIs  
10. Local FS writes  
11. Yes for out-of-band FS mutation  
12. Agent Server host

### Browser

1. `BrowserAction`  
2–8. Same pattern  
9. Possible if browser APIs exposed outside tools; primary path is tool-mediated  
10. Playwright Chromium in sandbox  
11. Yes for page JS / network after allow  
12. Agent Server host

### Context

1. User/repo/skill content in `MessageEvent` / prompt sections; OpenHands marks some repo content as `<UNTRUSTED_CONTENT>` in prompts  
2. Message admission / prompt assembly  
3. `UserPromptSubmit` can block or inject `additionalContext`  
4. Message text yes; full repo blob may be truncated  
5. Message block yes; does not by itself tag Harn.x provenance  
6. `blocked_messages` / modified `MessageEvent`  
7. Skip LLM or inject context  
8. Injected context visible; block ends turn  
9. Programmatic message injection paths  
10. Prompt assembly only  
11. N/A  
12. Agent Server / LocalConversation  

*(Harn.x must map untrusted introductions explicitly in the adapter — OpenHands does not emit Harn.x `context.introduced` natively.)*

### Skill

1. `invoke_skill` tool call / skill content load  
2. ActionEvent or context injection  
3. PreToolUse on invoke; content may land as prompt context without a tool  
4. Invoke args yes  
5. Tool path yes  
6. Standard rejection  
7–8. Standard  
9. Auto-injected repo skills into prompt bypass tool PreToolUse  
10. Skill body as text / scripts if skill runs tools later  
11. If skill triggers shell  
12. Host process

### Sub-agent

1. `delegate` / task tool ActionEvent  
2–8. Parent PreToolUse can deny spawn; child conversation has separate hooks  
9. Child with `hook_config=None` (agent-hook evaluators do this deliberately)  
10. Nested `LocalConversation`  
11. Child tools  
12. Same host (or remote child server)

### Session

1. Conversation create / SessionStart  
2. `ConversationState`  
3. SessionStart (non-blocking); SessionEnd  
4. Session metadata in HookEvent  
5. Not for create; Stop can prevent finish  
6. Stop deny → continue + feedback  
7–8. Agent continues  
9. Process kill  
10. Persistence / cleanup  
11. N/A  
12. Host

---

## 5. Choke Point Matrix

| Capability | Observable | Pre-execution | Post-execution | Blockable | Bypassable | Core-compatible |
|---|---|---|---|---|---|---|
| Tool/action | Yes (`ActionEvent`) | Yes (PreToolUse) | Yes (Observation / PostToolUse) | Yes | Yes (`execute_tool`, rerun) | Yes — map to `tool.requested` |
| Shell | Yes (`terminal`) | Yes | Yes | Yes | Yes (bash HTTP API, workspace cmd) | Yes — map `terminal`→`bash` args |
| File | Yes (`file_editor`) | Yes | Yes | Yes | Yes (`/api/file/*`) | Yes — map as tool |
| Browser | Yes | Yes | Yes | Yes | Partial | Yes — map as tool |
| Context | Partial (messages / UNTRUSTED tags) | UserPromptSubmit | N/A | Message only | Yes | Adapter must emit `context.introduced` |
| Skill | Partial | On `invoke_skill` | Yes | Tool path | Prompt auto-inject | Yes for tool path |
| Sub-agent | Yes (delegate tool) | Parent PreToolUse | Child events | Parent spawn | Child `hook_config=None` | Yes — `subagent.spawned` optional |
| Session | Yes | SessionStart (observe) | SessionEnd | Stop only | Process kill | Yes — `session.*` |

---

## 6. Harn.x attach path (no OpenHands fork)

Supported integration surface for Phase 2:

```text
HookConfig(pre_tool_use=[matcher terminal|* → command: harnx openhands-hook])
        │
        ▼ stdin JSON HookEvent
packages/harnesssec/src/adapters/openhands/
        │ maps → HarnessEvent
        ▼
Harn.x FlightRecorder + PolicyEngine (unchanged rules)
        │
        ▼ exit 2 + {"decision":"deny","reason":...}
OpenHands blocks ActionEvent → UserRejectObservation
```

Hooks run **inside** the Agent Server / LocalConversation process (sandbox when remote), not as a separate OS gate.

---

## 7. Implications for portability

| Requirement | OpenHands reality |
|---|---|
| Pre-exec intent | `ActionEvent` + PreToolUse — **available** |
| Full args | `tool_input` from `action.model_dump()` — **available** |
| Deny before side effect | `block_action` before tool body — **available** |
| Same Harn.x policy | Adapter must normalize `terminal`→shell semantics — **no rule rewrite** |
| Blind spots | Documented bash/file HTTP + `execute_tool` — **real** |
| Core changes | Only if schema lacks harness-generic fields (e.g. `harness.name` union) |

Phase 2 implementation must keep all vendor mapping under `packages/harnesssec/src/adapters/openhands/` and treat PreToolUse as the peer of DeepSeek `tools/pre-execute`.
