# OpenHands Blind Spots

**Phase 2.** Source-traced. Not invented.

Primary security hook for Harn.x: OpenHands **PreToolUse** on `ActionEvent` emission  
(`openhands-sdk/.../hooks/conversation_hooks.py` → `HookEventProcessor._handle_pre_tool_use`).

Anything that executes shell/FS/browser **without** emitting a hooked `ActionEvent` is invisible to Harn.x.

---

## Proven bypass (live)

### `LocalConversation.execute_tool(tool_name, action)`

**Evidence:** `openhands-sdk/.../conversation/impl/local_conversation.py` — docstring states this bypasses the agent loop / confirmation / security path. Calls `tool(action, conversation)` directly.

**Live proof** (`tests/integration/openhands_live.py`):

```text
touch /tmp/harnx-openhands-bypass-proof
```

via `execute_tool(TerminalTool.name, TerminalAction(...))` with Harn.x PreToolUse configured on the conversation → **file created**, no Harn.x `tool.requested` / deny.

This is the OpenHands peer of DeepSeek `ctx.shell.run`.

---

## Source-traced bypasses (not all live-exercised)

| Path | Why invisible | Source |
|---|---|---|
| `LocalConversation.rerun_actions` | Replays `tool()` without fresh ActionEvent hooks | `local_conversation.py` |
| Agent Server `BashEventService` / `/api/bash/*` | Subprocess shell outside conversation event stream | `agent_server/bash_service.py` |
| Agent Server `/api/file/*` | Direct FS API | `agent_server/file_router.py` |
| `Workspace.execute_command` / remote mixin | Hits bash HTTP API, not `terminal` tool | `workspace/remote/remote_workspace_mixin.py` |
| Direct `ToolDefinition.__call__` / executor | No hook awareness | `sdk/tool/tool.py` |
| Agent-hook sub-conversations | Created with `hook_config=None` (anti-recursion) | `hooks/executor.py` |
| Async PreToolUse | Runs but **cannot block** | `hooks/manager.py` warning |
| Prompt/agent hook fall-open | Parse/LLM failure → allow | `hooks/executor.py` `_fall_open` |
| Exit code `1` from command hooks | Non-blocking error; only exit `2` denies | `HookResult` contract |
| Auto-injected skills / repo prompt text | Enters context without `invoke_skill` ActionEvent | `sdk/context/`, skills loaders |

---

## What Harn.x still covers on OpenHands

When the agent loop emits `ActionEvent` and PreToolUse is wired to `harnesssec openhands-hook`:

- `terminal` intents (mapped to Harn.x `bash`)
- Other tools matched by hook matchers (`*`, `file_editor`, …)
- MCP tools registered on `tools_map` (same ActionEvent path)
- Parent `delegate` / task spawn (child may have separate hooks)

Denial surfaces as `UserRejectObservation(rejection_source="hook")` — visible to the model.

---

## Sandbox boundary note

Hooks and tools share the **Agent Server / LocalConversation host**. PreToolUse is not a kernel/seccomp gate. After allow, child processes, browser JS, and out-of-band APIs need OS/runtime telemetry (same Phase 4 gap as DeepSeek).

---

## Cover / uncover summary

```text
COVERED:  ActionEvent → PreToolUse → Harn.x policy → UserRejectObservation
UNCOVERED: execute_tool, rerun_actions, /api/bash, /api/file, workspace cmds,
           async/fail-open hooks, prompt-injected skill text, OS below tools
```
