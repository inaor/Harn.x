# Phase 1 Capabilities — Verified from Phase 0

Source of truth: [`deepseek-harness-architecture.md`](./deepseek-harness-architecture.md).

Only capabilities Phase 0 traced in DeepSeek Harness source are listed.
Nothing here is aspirational.

---

## OBSERVABLE

| Capability | Implementation | Hook / surface |
|---|---|---|
| Agent created / disposed | `packages/core/agent` | `agent/created`, `agent/disposed` (emit) |
| Agent status | `packages/core/agent-loop` | `agent/status` |
| Turn / step lifecycle | session log + driver | durable `turn/*`, `step/*` via `session/event` |
| Pre-step messages | `ReactLoopAgent.preStep` | `agent/pre-step` waterfall |
| Model request config | `ReactLoopAgent.buildRequest` | `agent/request` waterfall |
| Model stream | `packages/llm/llm` | `llm/stream` waterfall |
| Durable model I/O | session log | `request/header`, `assistant/chunk`, `assistant/message` via `session/event` |
| Tool call intent | `ToolRuntime` + agent loop | `tool/call` (session) + `tools/pre-execute` |
| Tool arguments (frozen) | `packages/core/tools` | `ToolExecution.arguments` on pre-execute |
| Tool result | `ToolRuntime.notifyResult` | `tools/result` emit + durable `tool/result` |
| MCP tool use | `packages/mcp/mcp-client` | same as tools; names `mcp__<server>__<raw>` |
| Shell command string | `packages/shell/tool-bash` | bash tool args on `tools/pre-execute` |
| FS mutation intent | `packages/fs/fs` + `tool-fs` | `fs/write-intent`, `fs/edit-intent`, `fs/observed` |
| Web tool URL/query | `packages/web/tool-web` | `web_fetch` / `web_search` args on `tools/pre-execute` |
| Context enter batch | `agent/pre-step` | claimed + entered messages |
| Message source kind | `packages/llm/llm` `MessageSource` | stamped on `user/message` (user / plugin / …) |
| Prompt assembly | `packages/core/system-prompt` | `system-prompt/assemble` |
| Skill catalog / skill tool | `packages/skill/tool-skill` | `agent/pre-step` inject + `skill` tool |
| Sub-agent start/end (in-process) | `packages/subagent/subagent` | `subagent/start`, `subagent/end` |
| Approval ask/decide | `packages/interaction/user-approval` | `approval/asked`, `approval/decided` |
| Session lifecycle | `packages/core/session` | `session/created`, `session/disposed`, `session/event` |
| Credential store update | `packages/credentials` | `credentials/updated` (write only) |
| Tool registry change | `packages/core/tools` | `tools/change` emit |

---

## INTERCEPTABLE

| Capability | How | Notes |
|---|---|---|
| Tool dispatch | `tools/pre-execute` waterfall | Runs before `ToolDefinition.execute` |
| Tool around-dispatch | `tools/execute` waterfall | Timeout / checkpoint style wrappers |
| Tool result shaping | `tools/post-execute` waterfall | After body (or after pre-deny path) |
| Step admission | `agent/pre-step` | Rewrite or reject entered messages |
| Model call config | `agent/request` | Provider / sampling only; messages frozen later |
| Model stream | `llm/stream` | Wrap / replace stream |
| FS write/edit | `fs/write-intent`, `fs/edit-intent` | Mutations only |
| Approval answers | `approval/request` waterfall | Separate from tools |

---

## MODIFIABLE

| Capability | How | Limits |
|---|---|---|
| Entered step messages | `agent/pre-step` → `{ kind: 'enter', messages }` | Yes |
| Prompt assembly | `system-prompt/assemble` | `complete` sections restored after waterfall |
| Tool result content | `tools/post-execute` → `accept` with content/value | Yes |
| Stream chunks | `llm/stream` wrapper | Yes |
| LlmCallConfig | `agent/request` | Not message bodies |
| Tool arguments | — | **Not modifiable** (frozen before pre-execute) |

---

## BLOCKABLE

| Capability | Decision | Body runs? |
|---|---|---|
| Tool call | `PreToolDecision` `{ kind: 'deny' }` | No |
| Tool call | `{ kind: 'ask' }` → not `allowed-once` | No |
| Tool call | `ctx.tools.guard()` reason | No |
| Completed tool result | `PostToolDecision` `{ kind: 'block' }` | Body already ran |
| Entire step | `agent/pre-step` `{ kind: 'reject' }` | No model call |
| FS mutation | throw / deny in `fs/*-intent` | Mutation skipped |
| Sub-agent spawn (tool) | deny parent spawn tool | Child not created |

---

## TERMINATABLE

| Primitive | Verified? | Scope |
|---|---|---|
| `agent.cancel({ kind: 'hook', reason })` | **Yes** — aborts active turn via `AbortController` | One agent turn |
| `AgentHandle.dispose()` | **Yes** — full teardown | Owner-only |
| Global process kill-switch | **No** | Does not exist |
| Hard-kill in-process tool ignoring `signal` | **No** | Cooperative only |

Phase 1 policy may use `TERMINATE` only as **cancel active turn** when an `Agent` reference is held — not process death.

---

## NOT OBSERVABLE

| Capability | Why |
|---|---|
| `process.exec` of shell children | No `subprocess/*` events |
| DNS / socket / TLS | No network seam events |
| HTTP destination of `bash -c 'curl …'` | Only outer command string visible |
| File I/O inside shell children | Bypasses `ctx.fs` / `fs/*` |
| Credential *resolve* reads | Only `credentials/updated` on write |
| Peer plugin admission | No global pre-mount gate |
| Out-of-process subagent tools | Separate runtime buses |
| Direct `ctx.shell` / `ctx.web` / `ctx.fs` calls | Bypass `tools/*` |
| Native `file.read` / `network.connect` events | Not harness primitives |

---

## REQUIRES CORE MODIFICATION

| Goal | Why |
|---|---|
| Force all capability calls through `tools/*` | Direct seams exist by design |
| Intercept every Node `spawn` / `fetch` | No events; would need provider wraps or OS |
| Sandbox untrusted plugins | Cordis is same-process trusted code |
| Argument rewriting at registry | Explicitly excluded in `PreToolDecision` |
| Guarantee auxiliary LLM calls hit `agent/request` | Compaction / titles bypass |
| Process-wide kill-switch | No API |

Seam **wrapping** (`ctx.subprocess`, `ctx.web`) is a plugin, not a core fork, but is **out of Phase 1 scope**.

---

## Phase 1 instrumentation allowlist

HarnessSec Phase 1 attaches only to:

```text
agent/created
agent/disposed
agent/pre-step
session/created
session/disposed
session/event          (durable firehose filter)
tools/pre-execute      (observe + BLOCK)
tools/post-execute     (observe)
tools/result           (observe)
tools/change           (capability inventory)
subagent/start
subagent/end
```

Optional (observe-only if present):

```text
approval/asked
approval/decided
llm/stream             (correlation; do not mutate in Phase 1)
```

Everything else is deferred.
