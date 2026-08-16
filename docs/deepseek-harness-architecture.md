# DeepSeek Harness — Security Architecture Map

**Phase 0 deliverable.** Source-traced. No product code.

Studied checkout: `deepseek-harness/` (https://github.com/deepseek-ai/deepseek-harness), developer preview, compatibility-breaking changes expected.

This report answers one question:

> Can security-relevant agent execution be observed and controlled at the harness layer without maintaining a large fork of DeepSeek Harness?

**Short answer: yes for agent intent and tool-mediated actions. No for what child processes actually do on the OS.**

A HarnessSec adapter can be a normal out-of-tree Cordis plugin. The official hook surface is already used by first-party policy plugins. A large core fork is not required for Phase 1–3. Runtime / OS telemetry is still required for Phase 4 gaps.

---

## 1. What DeepSeek Harness actually is

`dsh` is not a monolithic agent loop with a few extension points. It is a Cordis plugin tree. Official architecture (`docs/architecture.md`):

> There is no privileged core to patch: you extend dsh by mounting a plugin beside the others.

A running process is composed at boot:

```text
empty entry list
    → each bundle in the profile (dsh-base, then web-app or headless)
    → profile cordis.patch.yml
    → home-level patch
    → --patch overlay
```

`dsh-base` already mounts model adapters, tools, persistence, sandbox, approval, credentials, and telemetry. Third-party plugins install with:

```text
dsh plugin --profile <name> add <package-or-git-spec>
```

That is the supported HarnessSec attach path. No fork.

### Core owners

| Package | Owns | `ctx` key |
|---|---|---|
| `packages/core/session` | Append-only session log | `ctx.sessions` |
| `packages/core/system-prompt` | Prompt assembly | `ctx.systemPrompt` |
| `packages/core/tools` | Tool registry + guarded pipeline | `ctx.tools` |
| `packages/core/agent` | Agent interface + `agent/*` events | `ctx.agents` |
| `packages/core/agent-loop` | Default driver | `ctx.agentLoop` |
| `packages/llm/llm` | Model stream seam | `ctx.llm` |
| `packages/shell/shell` | Shell executor seam | `ctx.shell` |
| `packages/subprocess/subprocess` | Process spawn seam | `ctx.subprocess` |
| `packages/fs/fs` | Filesystem seam + `fs/*` events | `ctx.fs` |
| `packages/web/web` | Search / fetch seam | `ctx.web` |
| `packages/sandbox/sandbox` | File-effect confinement | `ctx.sandbox` |
| `packages/interaction/user-approval` | Ask / never policy | `ctx.approval` |
| `packages/skill/skill` | Skill registry | `ctx.skills` |
| `packages/subagent/subagent` | Child-agent registry | `ctx.subagents` |
| `packages/credentials/credentials` | Secret resolve / store | `ctx.credentials` |
| `packages/mcp/mcp-client` | MCP connection + tool sync | (registers into `ctx.tools`) |

---

## 2. Turn flow — the real interception map

From `docs/architecture.md` and `packages/core/agent-loop/src/agent.ts`:

```text
turn/start
  claim inbox + queued message
  assemble prompt sections + tool schemas
  -> agent/pre-step                 reject | enter(messages)
     reject or empty first enter -> close turn, no step
     step/start
     append entered messages as user/message
     derive model history from the log
     agent/request -> llm/stream -> assistant/chunk* -> assistant/message
     tool/call*
       -> tools/pre-execute         allow | deny | ask
       -> monotonic guards
       -> tools/execute             around dispatch
       -> ToolDefinition.execute()
       -> tools/post-execute        accept | replace | block
       -> tools/result              observe frozen outcome
     -> tool/result*
     step/end
  -> agent/turn-stopping
turn/end
```

Waterfalls (`agent/pre-step`, `agent/request`, `llm/stream`, `tools/pre-execute`, `tools/execute`, `tools/post-execute`) require listeners to call `next()` to delegate. A listener that does not call `next()` vetoes the rest of the chain (`vendor/cordis/src/events.ts`).

Durable facts (`turn/*`, `step/*`, `user/message`, `assistant/*`, `tool/*`) are session-log events, then broadcast on `session/event`. Live hooks are Cordis events. Do not confuse the two.

---

## 3. Capability traces

For every capability: where it lives, what happens immediately before/after, official hook, observe / modify / deny / result / cancel, bypass, fork required.

### 3.1 Tool invocation

**Where.** `ToolRuntime` in `packages/core/tools/src/index.ts`. Agent loop dispatch in `packages/core/agent-loop/src/tool-calls.ts` (`executeToolCalls`).

**Owner.** `ctx.tools`.

**Before.** Session appends `tool/call`. Then `tools/pre-execute` waterfall. Then `ctx.approval.request()` if the decision is `ask`. Then monotonic `ctx.tools.guard()`.

**After.** `tools/post-execute`, optional `finalizeContent`, then emit-only `tools/result`, then durable `tool/result`.

**Official interface.**

```ts
type PreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'ask'; reason?: string }

type PostToolDecision =
  | { kind: 'accept'; content?: ContentBlock[] }
  | { kind: 'accept'; value: JsonValue }
  | { kind: 'block'; feedback: ContentBlock[] }
```

Deny is a **returned decision**, not a throw. The tool body does not run. The model sees an error tool result. Post-execute `block` converts a completed call into `isError: true`.

**Observe.** Yes — frozen args on pre-execute; frozen outcome on `tools/result`.

**Modify args.** No. Arguments are snapshotted and frozen before pre-execute. Input rewriting is explicitly excluded.

**Deny.** Yes — `{ kind: 'deny' }` or `{ kind: 'ask' }` that fails closed. Guards cannot be overridden by later pre-execute listeners.

**Observe result.** Yes — `tools/post-execute` (mutable) and `tools/result` (immutable).

**Terminate session.** Not from the tool waterfalls. A tool body may call `exec.concludeTurn()`. A plugin holding an `Agent` may call `agent.cancel()`.

**Bypass.**

- Direct `ToolDefinition.execute()` (holds a captured definition)
- Direct capability calls: `ctx.web.fetch`, `ctx.fs.*`, `ctx.shell.run`
- `ctx.commands.execute()` (human commands, not tools)
- Code-mode collapse of model-direct non-`run_code` calls (hard deny before pre-execute)
- Out-of-process subagents (Codex, Claude Code, ACP)

**Fork required.** No for model-originated tool calls. Yes to force every in-process capability call through the pipeline.

**Existing listeners (proof the seam is real).**

| Plugin | Event | Behavior |
|---|---|---|
| `dsh-hooks-claude-code` | pre / post | Maps Claude `PreToolUse` / `PostToolUse` to allow / deny / ask / block |
| `dsh-hooks-codex` | pre / post | Codex hook bridge; deny only |
| `dsh-tool-call-timeout-policy` | execute | Deadline on `exec.signal` |
| `dsh-session-checkpoint-policy` | execute | Flush session before body |
| `dsh-spill-policy` | post | Replace oversized text |
| `dsh-repeat-tool-reminder` | post | Observe only; inject context |

HarnessSec should look like those plugins, not like a fork.

---

### 3.2 MCP invocation

**Where.** `packages/mcp/mcp-client/src/index.ts` (`startConnection`) and `src/tools.ts` (`syncTools`, `createExecutor`).

**Owner.** MCP client plugin. Tools land on `ctx.tools` as `mcp__<serverName>__<rawName>`.

**Before / after.** Same as any other tool. MCP `tools/call` happens **inside** `ToolDefinition.execute`, after pre-execute and guards.

**Official interface.** None MCP-specific for policy. Use `tools/*`.

**Observe / deny / result.** Yes, identical to native tools. Filter on the `mcp__` name prefix if needed.

**Bypass.** Direct MCP SDK use outside the client plugin. MCP server process itself is trusted executable code outside the agent sandbox (CLI reference states this explicitly). Child activity of the MCP server is invisible.

**Fork required.** No for tool-mediated MCP. Yes to inspect the MCP server process.

---

### 3.3 Shell execution

**Where.**

| Layer | Path | Role |
|---|---|---|
| Seam | `packages/shell/shell/src/index.ts` | `ctx.shell` |
| Local | `packages/shell/bash-local/src/index.ts` | `bash -c` via `ctx.subprocess` |
| Sandboxed | `packages/shell/bash-sandbox/src/index.ts` | wraps argv with `ctx.sandbox.confine` |
| Model tool | `packages/shell/tool-bash/src/index.ts` | `bash` tool |
| Persistent | `packages/shell/tool-bash-persistent/src/index.ts` | PTY via `ctx.terminals` |

**Before.** Tool pipeline, then sandbox policy resolve, optional approval for escalation, `ctx.shellEnv.collect`, `ctx.shell.run`.

**After.** Tool post-execute / result. Sandbox denials inferred from backend-specific stderr signatures.

**Official interface.** `tools/*` only. **No `shell/*` events.**

**Observe.** Command string at tool-call time. Not inner commands after `bash -c`.

**Deny.** Yes at `tools/pre-execute` (the command never starts). After spawn, only cooperative cancel via `AbortSignal`.

**Bypass.**

- `bash -c "curl …"` — harness sees the shell command, not the HTTP connect
- Persistent PTY — confinement is at spawn, not per inner command
- Direct `ctx.shell.run()` from other plugins (Claude/Codex hook runners do this)
- `danger-full-access` skips `ctx.sandbox`

**Fork required.** No for observing/blocking the model-facing `bash` tool. Yes (or OS telemetry) for child-process behavior.

`tool-bash` itself documents the intended policy home:

> deployment policy belongs in `tools/pre-execute` and sandboxing executors

---

### 3.4 Process creation

**Where.** `packages/subprocess/subprocess/src/index.ts` (`SubprocessRuntime`), local spawn in `packages/subprocess/subprocess-local/src/spawn.ts` (`node:child_process.spawn`, POSIX `detached: true`).

**Owner.** `ctx.subprocess`.

**Before / after.** Env scrub (`SENSITIVE_ENV_PATTERN` = `/KEY|PASSWORD|SECRET|TOKEN/i`, plus `DSH_*`). No Cordis events.

**Official interface.** None.

**Observe / deny.** Not through a supported hook. A wrapper provider could replace `ctx.subprocess`. That is still a plugin, not a core fork, but it is a seam wrap rather than an event.

**Bypass.** `spawnSync` in host code, SDK-managed subagent processes (`subagent-dsh-sdk`), shell grandchildren, vendor packages.

**Fork required.** Not strictly — a replacement `SubprocessRuntime` plugin can wrap spawn. Complete coverage of every Node spawn still needs OS telemetry.

---

### 3.5 File access

**Where.** `packages/fs/fs/src/index.ts` (`ctx.fs`), local backend `fs-local`, fence `fs-sandbox`, observation `fs-observation-policy`, model tools `tool-fs`.

**Events.**

| Event | Mode | Role |
|---|---|---|
| `fs/write-intent` | waterfall | Derive write intent |
| `fs/edit-intent` | waterfall | Require prior read / CAS version |
| `fs/observed` | emit | Record presence after read/write |

**Before.** Tool pipeline for model tools. Mutation tools then run `fs/write-intent` or `fs/edit-intent`.

**After.** `fs/observed` emit. Tool result.

**Observe.** Tool-mediated reads/writes: yes (tool args + `fs/*`). Arbitrary reads via `ctx.fs.readText`: no intent event.

**Deny.** Yes for mutations (`FS_SANDBOX_DENIED`, `FS_NOT_OBSERVED`). Reads are not gated by `fs/*`.

**Bypass.**

- Shell writing files — bypasses `ctx.fs` entirely; only process sandbox file policy applies
- `grep` / `glob` via unconfined ripgrep (`ctx.subprocess`)
- Skill filesystem fallback to Node `fs/promises` when `ctx.fs` is absent
- Credentials / settings files use Node FS, not `ctx.fs`
- `danger-full-access` removes the fence

**Fork required.** No for tool-fs mutations. Yes / OS telemetry for shell-mediated and Node-direct I/O.

---

### 3.6 Network access

**Where.** `ctx.web` (`packages/web/web`), HTTP provider `web-fetch-http` (`fetch` with `redirect: 'manual'`), model tools `web_search` / `web_fetch`. LLM adapters call `fetch` directly.

**Official interface.** `tools/*` for the two web tools. **No `web/*` events.**

**Observe / deny.** Yes for `web_fetch` / `web_search` at pre-execute. The HTTP provider documents that private-network / SSRF protection is **not implemented**.

**Bypass.**

- Shell `curl` / `wget` / language HTTP clients
- LLM provider `fetch` (model API, also search backends)
- Direct `ctx.web.fetch`
- Out-of-process subagent stacks

**Fork required.** No for the two web tools. Yes or OS/proxy telemetry for real egress.

---

### 3.7 Context modification

**Where.** `ctx.systemPrompt.assemble` (`packages/core/system-prompt`), `agent/pre-step`, `agent.inject()` / `steer()` / `followup()`, `session.deriveMessages()`.

**Official interface.** `system-prompt/assemble` waterfall; `agent/pre-step`.

**Observe.** Yes — assembled prompt, claimed messages, durable log.

**Modify.** Yes — rewrite entered messages; transform assembly. `complete` system-prompt sections are restored after the waterfall, so a listener cannot permanently replace the system prompt.

**Deny.** `agent/pre-step` → `{ kind: 'reject' }` closes the turn with no model call.

**Bypass.** Compaction rewrite of history; runtime-context projection; detached `agent/session-start` inject that can miss the first request.

**Fork required.** No for turn-time context. Yes to intercept every `Session.append()` before commit.

---

### 3.8 Plugin loading

**Where.** Cordis Loader (`vendor/loader`), Include / patches (`vendor/include`), profile composer (`packages/boot/app-boot`), CLI `apps/cli/src/plugin.ts`.

**Official interface.** Package `apply(ctx)`, `inject` deps, `cordis.patch.yml` bundle declaration. Dynamic plugins: `ctx.dynamicCordisRunner` (`packages/extensions`).

**Observe.** A security plugin can list Loader entries and listen to fiber lifecycle. There is no global pre-mount admission hook for every plugin.

**Deny.** Failed `apply()` prevents that plugin from loading. There is no supported “block this other plugin from loading” API unless HarnessSec owns composition (profile patch / wrapper).

**Bypass.** Dynamic Cordis packages defined by the agent; MCP servers; same-process `import`.

**Fork required.** Yes for untrusted-plugin sandboxing. Cordis assumes trusted same-process code. HarnessSec as a plugin is trusted code with the same privileges as every other plugin.

This is a first-class threat: a malicious plugin is not contained by HarnessSec hooks.

---

### 3.9 Skill execution

**Where.** `ctx.skills` (`packages/skill/skill`), model tool + catalog injection (`packages/skill/tool-skill`).

**Before.** `agent/pre-step` injects a skill catalog. User `/skill-name` is also scanned there. Model `skill` tool goes through `tools/*`.

**Observe / deny.** Yes via `agent/pre-step` reject and `tools/pre-execute` on the `skill` tool.

**Bypass.** `disable-model-invocation` skills still reachable via user gesture. Skill body content is not scanned by a dedicated security event.

**Fork required.** No for standard paths.

---

### 3.10 Sub-agent creation

**Where.** `ctx.subagents` (`packages/subagent/subagent`), in-process driver (`subagent-in-process-driver`), spawn provider (`subagent-spawn-in-process`), model tool (`tool-subagent`).

**Events.** `subagent/start`, `subagent/end` (emit). Child is created with `parent.ctx.agents.create(...)`.

**Observe.** Yes for in-process children (`subagent/*` + the child's own `agent/*` / `tools/*` if HarnessSec is in that scope).

**Deny.** Parent `tools/pre-execute` can deny the spawn tool. Child `agent/pre-step` can reject. Parent abort → `child.cancel({ kind: 'parent' })`.

**Bypass.** Out-of-process providers: `subagent-acp`, `subagent-codex`, `subagent-claude-code`. Those run other products. Their tool use is not on this process's `tools/*` bus.

**Fork required.** No to observe in-process children. Yes to force every external delegation through a wrapper.

---

### 3.11 Session termination / cancellation

**Where.** `ReactLoopAgent.cancel()` in `packages/core/agent-loop/src/agent.ts`. Disposal in `packages/core/agent-loop/src/index.ts`.

```ts
cancel(cause: AgentCancelCause, options: CancelOptions = {}): void {
  if (!options.keepInbox) this.inbox.clear()
  if (this.phase.kind !== 'idle') this.phase.abort.abort(cause)
}

type AgentCancelCause =
  | { kind: 'user' }
  | { kind: 'parent' }
  | { kind: 'hook'; reason: string }
  | { kind: 'disposed' }
```

**This is real cooperative cancellation**, not a fake flag. The active turn's `AbortSignal` is checked at pre-step, stream iteration, and tool execute. Tools that ignore `exec.signal` cannot be hard-killed in-process (documented on `ToolDefinition.execute`).

**There is no global kill-switch primitive.** No emergency-stop API. `agent/turn-stopping` can `steer()` another step — the opposite of kill.

| Action | Effect |
|---|---|
| `agent/pre-step` reject | Blocks one turn |
| `tools/pre-execute` deny | Blocks one tool |
| `agent.cancel({ kind: 'hook', reason })` | Aborts the active turn |
| `AgentHandle.dispose()` | Full teardown; owner-only |
| Unload HarnessSec fiber | Removes our hooks only |

**Fork required.** No for turn cancel if the plugin holds an `Agent`. Yes for a process-wide kill switch.

---

### 3.12 Model request / response

**Where.** `packages/core/agent-loop/src/agent.ts` (`buildRequest`, `step`), `packages/llm/llm/src/index.ts` (`llm/stream` waterfall).

**Observe.** `agent/request` (config), `llm/stream` (frozen request + chunk stream), durable `request/header`, `assistant/chunk`, `assistant/message`.

**Modify.** Replace provider / sampling on `agent/request`. Wrap or replace the stream on `llm/stream`. Cannot mutate loop-built messages (deep-frozen).

**Deny.** Indirect — invalid config throws; stream can be short-circuited; `agent/pre-step` reject is the clean deny.

**Bypass.** Auxiliary `GenerateOptions.purpose` calls (compaction, session title) skip `agent/request`. Direct adapter use.

**Fork required.** No for the main loop path. Yes to guarantee every provider HTTP call.

---

## 4. Choke-point matrix

Filled from the traces above. Not from marketing names.

| Capability | Observable | Pre-execution hook | Post-execution hook | Blockable | Requires core change |
|---|---|---|---|---|---|
| Tool invocation | Yes — `tools/pre-execute`, `tool/call` | `tools/pre-execute`, `ctx.tools.guard` | `tools/post-execute`, `tools/result` | Yes — deny / ask / guard / post block | No |
| MCP invocation | Yes — same pipeline, `mcp__*` names | Same as tools | Same as tools | Yes, as a tool | No |
| Shell execution | Command string only | `tools/pre-execute` on `bash` | `tools/post-execute` / result | Yes before spawn | No for the tool; yes/OS for children |
| Process creation | Not via events | None | None | Only by wrapping `ctx.subprocess` | Seam wrap or OS |
| File access (tool-fs) | Yes — args + `fs/*` | `tools/pre-execute`, `fs/*-intent` | `fs/observed`, tool result | Mutations yes; reads weak | No |
| File access (shell child) | No | No | No | Only sandbox file-effect | OS / sandbox |
| Network (web tools) | URL / query | `tools/pre-execute` | Tool result | Yes | No |
| Network (shell / LLM / DNS) | No | No | No | No | OS / proxy |
| Context modification | Yes | `agent/pre-step`, `system-prompt/assemble` | Session log | Reject step | No |
| Plugin loading | Partial | None global | Fiber dispose | Not for peers | Yes for isolation |
| Skill execution | Yes | `agent/pre-step`, `tools/pre-execute` | Tool result | Yes | No |
| Sub-agent creation (in-process) | Yes — `subagent/start` | Parent tool pre-execute | `subagent/end` | Yes | No |
| Sub-agent (external product) | Spawn intent only | Parent tool only | Weak | Parent tool only | Yes / other adapter |
| Session termination | `session/disposed`, cancel cause | `agent.cancel` / dispose | — | Cancel turn: yes. Kill process: no | No for cancel |
| Model request | Yes — `llm/stream`, log | `agent/pre-step`, `agent/request` | chunks / message | Reject step | No for main path |
| Credential resolve | `credentials/updated` on write | None on `resolve()` | None | No | Wrap provider |
| Sandbox policy | Mode / enforcement fact | `ctx.sandboxPolicy` | stderr / FS errors | File writes only | N/A |

---

## 5. Two telemetry layers — validated

The research brief hypothesized a split. The code confirms it.

### Layer 1 — Harness telemetry (available now)

These are real, documented, plugin-visible:

```text
agent/created, agent/disposed, agent/status
agent/pre-step, agent/request, agent/turn-stopping
session/created, session/event, session/disposed
tool/call, tool/result
tools/pre-execute, tools/execute, tools/post-execute, tools/result
llm/stream
fs/write-intent, fs/edit-intent, fs/observed
subagent/start, subagent/end
approval/asked, approval/decided
hook/invoked, hook/result
credentials/updated
```

These answer: **why did the agent attempt this?**

Shipped capture already exists: `ctx.sessionTelemetry` + optional OTel exporter (`session-telemetry-otel`). That is an export path, not a security policy engine.

### Layer 2 — Runtime / OS telemetry (not available from plugins)

Confirmed invisible:

```text
DNS lookup
socket / TLS connect
HTTP destination of shell children
grandchild processes
file I/O performed by bash / python / curl
credential file reads via cat ~/.aws/credentials
IPC
container / host persistence
```

`ctx.sandbox` is **file-effect only**. From `docs/subsystems/sandbox.md`:

> Network and process visibility are outside this vocabulary.

Modes: `read-only` | `workspace-write` | `danger-full-access`. Linux: bwrap then Landlock. macOS: Seatbelt. Windows: ACL restricted token (partial). A confined `curl` still talks to the network.

These answer: **what actually happened on the system?**

---

## 6. First-demo honesty

The research brief's ideal demo:

```text
cat ~/.aws/credentials     → credential detection
curl …                     → block as exfil sequence
```

**What is actually true today:**

| Demo step | Honest status |
|---|---|
| Attach as a plugin without forking | Supported (`dsh plugin add`) |
| Observe `agent.started` | Yes — `agent/created` / session start |
| Observe `tool.requested` / `bash` | Yes — `tools/pre-execute` + `tool/call` |
| See command `cat ~/.aws/credentials` | Yes — tool arguments |
| Classify path as credential material | Yes — **enrichment**, not native `file.read` |
| Block that bash call | Yes — `{ kind: 'deny' }` before spawn |
| See a later `curl` bash call | Yes — next tool args |
| Sequence-detect “secret then egress” | Yes — if both are **tool-visible bash strings** |
| Claim `file.read` telemetry | **No** — shell children do not emit `fs/*` |
| Claim `network.connect` telemetry | **No** — not a harness event |
| Prove `curl` did not execute | Yes **only if** we denied the bash tool before `ctx.shell.run` |
| See `curl` inside `bash -c 'cat … && curl …'` as two events | **No** — one shell command |

Valid Phase 1 demo (do not overclaim):

```text
$ harnesssec run dsh

HarnessSec attached
Harness: DeepSeek DSH

agent.started
tool.requested   bash
shell.requested  cat ~/.aws/credentials
policy.match     credential-material-in-tool-args
action           DENY
tool.result      isError  (body never ran)
```

A later `bash` whose command string contains `curl` can be a second deny. That is command-string policy, not network telemetry.

---

## 7. Phase 0 success criteria

| Question | Answer |
|---|---|
| Can we observe tool calls? | **Yes.** `tools/pre-execute`, `tool/call`, `tools/result`. |
| Can we intercept before execution? | **Yes.** Waterfall + monotonic guards. |
| Can we block tool calls? | **Yes.** `deny` / failed `ask` / guard. Body skipped. |
| Can we observe MCP activity? | **Yes.** MCP tools are `mcp__*` tools on the same pipeline. |
| Can we intercept MCP activity? | **Yes**, as tools. Not the MCP server process. |
| Can we observe shell execution? | **Command string yes.** Child syscalls no. |
| Can we prevent shell execution? | **Yes** before spawn. Not mid-command hard-kill unless the tool honors abort. |
| Can we observe context changes? | **Yes.** `agent/pre-step`, prompt assemble, session log. |
| Can we observe plugin/skill loading? | **Partial.** Skills yes. Peer plugin admission no. |
| Can we observe sub-agent creation? | **Yes** in-process. External products only at the spawn tool. |
| Can we terminate/cancel a session? | **Turn: yes** (`agent.cancel`). **Process: no** dedicated API. Dispose is owner-only. |
| What happens below the harness? | Child processes, DNS, sockets, Node FS, LLM HTTP, MCP server code. |
| What needs OS/runtime telemetry? | Everything in the previous row, plus `danger-full-access` and external subagents. |
| What bypasses instrumentation? | Direct `ctx.*` calls, commands, captured `.execute()`, shell children, external runtimes, malicious peer plugins. |
| Can this be done without a large fork? | **Yes** for Layer 1. Official plugin install + Cordis events. |

---

## 8. Recommended HarnessSec attach shape

Do not fork `packages/core/tools` or `agent-loop`.

```text
@harnesssec/dsh-adapter          # Cordis plugin
  inject: ['tools', 'agents', 'sessions']
  apply(ctx):
    ctx.on('tools/pre-execute',  observe + deny)
    ctx.on('tools/post-execute', observe + block)
    ctx.on('tools/result',       immutable outcome)
    ctx.on('agent/pre-step',     optional reject)
    ctx.on('agent/created',      bind agent ref for cancel)
    ctx.on('session/event',      durable firehose)
    ctx.on('subagent/start',     child correlation)
    ctx.tools.guard(...)         monotonic last-line deny
```

Install:

```text
dsh plugin --profile web add <harnesssec-adapter>
```

Optional later, still not a fork:

- Wrap `ctx.subprocess` for argv-level spawn visibility
- Wrap `ctx.web` if a `web/*` event is never added upstream
- Listen `approval/request` if we want to be an answerer

Do **not** implement argument rewriting. The registry forbids it.

Do **not** claim `file.read` / `network.connect` until a Layer 2 sensor exists.

---

## 9. Threat model mapped to real controls

| Threat | Harness control that exists | Gap |
|---|---|---|
| Tool abuse | `tools/pre-execute` deny | None for tool-mediated calls |
| Indirect prompt injection | `agent/pre-step` can reject; context is logged | Detection is ours to write; no built-in IPI detector |
| MCP abuse | Same tool pipeline | MCP server process is trusted and unsandboxed |
| Malicious plugins | None | Same-process, full `ctx` |
| Malicious skills | Tool / pre-step deny | Body not scanned |
| Credential exposure | Env scrub heuristic; `credentials/updated` | `cat ~/.aws/credentials` is just a bash string; `resolve()` has no read hook |
| Data exfiltration | Deny `web_fetch` / bash `curl` strings | Real sockets invisible |
| Excessive permissions | `ToolRestriction` allow/deny; approval `never`; sandbox modes | Easy to set `danger-full-access` |
| Destructive execution | Deny dangerous bash strings | `rm` inside a script file is not visible as `rm` |
| Sub-agent abuse | Observe in-process; parent cancel | External products leave the bus |
| Supply-chain | Profile pin / plugin add | No admission control |
| Control bypass | Documented above | Shell children, direct seams, peer plugins |

---

## 10. Phase 1 boundary (do not start until this report is accepted)

Minimum viable sensor, if Phase 0 is accepted:

1. Out-of-tree Cordis plugin on `tools/pre-execute` + `tools/result` + `session/event`.
2. Normalize only events that have a documented source.
3. CLI that prints those events while `dsh` runs.
4. One deterministic rule: deny bash/tool args that name known credential paths.
5. Prove the bash body did not run (error result, no subprocess).

Out of scope until later phases: dashboard, SaaS, ML detections, `file.read` / `network.connect` schema, global kill switch, subprocess wrapper, eBPF.

---

## 11. Verdict

DeepSeek Harness is a strong adapter #1.

The product thesis survives contact with the code:

- The harness is a real observation and enforcement point.
- Official waterfalls already implement allow / deny / ask / block.
- First-party hook bridges prove a third-party security plugin is the intended extension style.
- A large fork is not required for Layer 1.

The product thesis also has a hard ceiling:

- Harness telemetry is **intent and orchestration**.
- Runtime telemetry is still required for **actual execution**.
- Sandbox does not equal network EDR.
- Plugins are trusted peers, not a security boundary against each other.

That is enough to proceed to a plugin-only Phase 1 sensor. It is not enough to claim Agent Runtime Detection & Response as a finished category.
