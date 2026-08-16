# Blind Spots

HarnessSec (Harn.x) instruments **harness intent**, primarily via `tools/*` waterfalls.
The following are confirmed gaps. Do not claim coverage of them.

---

## 1. Direct `ctx.shell` (CONFIRMED)

**Test:** `tests/integration/dsh-live.test.ts` — bypass case.

A peer (or any code holding `ctx.shell`) can:

```ts
const spec = ctx.shell.resolve({ command: 'touch /tmp/harnx-bypass-proof', workdir })
await ctx.shell.run(spec)
```

Result:

- File is created
- Harn.x emits **no** `tool.requested` / `shell.command_requested` for that command

**Why:** Shell is a capability seam. Policy on `tools/pre-execute` only sees model/tool-pipeline calls.

**Mitigation (future, not Phase 1):** wrap `ctx.subprocess` / `ctx.shell` providers; OS telemetry.

---

## 2. Direct `ctx.web` / `ctx.fs` / `ToolDefinition.execute()`

Same class of bypass: capability seams reachable without the tool waterfall.

---

## 3. Shell child processes

Even when bash is observed, `bash -c 'curl …'` only exposes the **outer command string**.
DNS, sockets, and grandchild processes are not harness events.

---

## 4. Out-of-process subagents

Codex / Claude Code / ACP providers run outside this process’s `tools/*` bus.

---

## 5. Peer plugins

Cordis plugins are same-process trusted code. Harn.x cannot sandbox a malicious peer.

---

## 6. Credential resolve reads

`credentials/updated` is write-side. `resolve()` is not a read hook.

---

## Honest product boundary

```text
COVERED:  tool intent, pre-exec deny, session/agent/context (turn-scoped), MCP naming+trust config
NOT COVERED: OS execution below the harness, direct seams, peer malice
```
