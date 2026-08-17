# Cursor Integration Architecture (Phase 4A.0)

Evidence sources (no private reverse engineering):

- [Cursor Agent Hooks](https://cursor.com/docs/agent/hooks) (fetched for this phase)
- [Third Party Hooks](https://cursor.com/docs/reference/third-party-hooks)
- Local Cursor create-hook skill (`~/.cursor/skills-cursor/create-hook`)
- Local Cursor.app version tested for this alpha: **3.13.10**

## Product invariant

> Native harness integrations must not require access to model-provider credentials.

Cursor owns the model and agent loop. Harn.x observes and governs through
**supported hooks only**.

## Native Harness Mode vs Laboratory Mode

| Mode | Model credentials | Agent loop | Harn.x role |
|---|---|---|---|
| **Native (Cursor)** | Cursor's | Cursor Agent | Hooks → adapter → policy/behavior |
| **Laboratory (DSH/OH)** | External `HARNX_TEST_*` / provider keys | Experiment runner | Research / Phase 3.2 only |

External API keys are **not** part of Cursor native alpha.

## Plugin vs hooks architecture

Cursor documents two related surfaces:

1. **Hooks** — `hooks.json` at project (`.cursor/hooks.json`) or user (`~/.cursor/hooks.json`) level; command or prompt hooks exchanging JSON over stdio.
2. **Plugins / Customize** — docs note hooks can also be installed through plugins from **Customize**; Marketplace packaging for Harn.x is **out of scope** for Phase 4A (no invented install command).

Phase 4A uses **official command hooks** only.

### Configuration locations (priority, highest first)

Per Cursor third-party hooks docs:

1. Enterprise hooks  
2. Team hooks (dashboard)  
3. Project hooks (`.cursor/hooks.json`)  
4. User hooks (`~/.cursor/hooks.json`)  
5. Claude Code project/user settings (optional compatibility)

### Local developer installation (exact, supported)

**Project (lab / shared via VCS):**

```bash
# In the workspace Cursor opens:
# .cursor/hooks.json  +  .cursor/hooks/* scripts
# Cursor reloads hooks on save; restart if needed.
# Debug: View → Output → Hooks
```

**User-global (optional “always on”):**

```bash
mkdir -p ~/.cursor/hooks
# ~/.cursor/hooks.json with commands relative to ~/.cursor/
```

There is **no** supported `harnx install cursor` Marketplace command yet. Intended UX is documented in `phase4a-cursor-alpha.md`; alpha uses project hooks in the controlled lab.

## Hook categories

| Category | Hooks | Phase 4A use |
|---|---|---|
| Agent | session*, pre/postToolUse*, subagent*, before/after Shell/MCP, beforeReadFile, afterFileEdit, beforeSubmitPrompt, preCompact, stop, afterAgent* | Primary |
| Tab | beforeTabFileRead, afterTabFileEdit | Blind spot / out of Agent proof |
| App | workspaceOpen | Out of Agent proof |

## Canonical enforcement proof (locked)

| Rule | Requirement |
|---|---|
| Hook | **`beforeShellExecution` only** for Required Proof 1 |
| Config | `failClosed: true` |
| Decision | `permission: "deny"` |
| Do not use | `permission: "ask"` for the canonical test |

## subagentStart (locked)

Observation-only until enforcement is proven with **side-effect / runtime evidence**.
Do **not** claim reliable subagent blocking from hook JSON response alone.

## Payload persistence (locked)

`beforeReadFile` may deliver full `content` to the hook process. Harn.x must:

- **not** persist full file contents by default
- prefer path, metadata, trust/provenance, content hash
- use redacted excerpts only when a security primitive requires them

## Per-hook capability matrix

Legend: Y = yes documented · N = no/unsupported · P = partial · U = unknown/unverified live

### sessionStart

| Question | Answer |
|---|---|
| Observable before execution? | Session creation; **fire-and-forget** (agent does not wait for blocking response) |
| Arguments visible? | Common schema + session fields (`session_id` ≈ conversation) |
| Can execution be denied? | N (not a blocking gate) |
| Can result be modified? | Context/env injection fields per docs; not used for Action B |
| Does denial return to the agent? | N/A |
| Session ID exposed? | Y (`session_id` / `conversation_id`) |
| Agent ID exposed? | N (no separate agent id in common schema) |
| Context provenance exposed? | N |
| Subagent/delegation exposed? | N |
| Bypass paths? | Cloud agents may omit sessionStart; see blind spots |

### sessionEnd

| Question | Answer |
|---|---|
| Observable before execution? | After session ends |
| Arguments visible? | Session id / status-ish fields |
| Can execution be denied? | N |
| Can result be modified? | N |
| Does denial return to the agent? | N/A |
| Session ID exposed? | Y |
| Agent ID exposed? | N |
| Context provenance exposed? | N |
| Subagent/delegation exposed? | N |
| Bypass paths? | Cloud: not available (IDE lifetime) |

### beforeSubmitPrompt

| Question | Answer |
|---|---|
| Observable before execution? | Y — after send, before backend request |
| Arguments visible? | Prompt text + attachments |
| Can execution be denied? | Y via `continue: false` |
| Can result be modified? | N (block or allow submit) |
| Does denial return to the agent? | User message; prompt not sent |
| Session ID exposed? | Y (`conversation_id`) |
| Agent ID exposed? | N |
| Context provenance exposed? | Attachments paths only |
| Subagent/delegation exposed? | N |
| Bypass paths? | Tab / non-Agent paths |

### preToolUse

| Question | Answer |
|---|---|
| Observable before execution? | Y (all tools) |
| Arguments visible? | `tool_name`, `tool_input`, `tool_use_id` |
| Can execution be denied? | Y `permission: "deny"`; **`ask` not enforced** for preToolUse today |
| Can result be modified? | Y `updated_input` |
| Does denial return to the agent? | Y `agent_message` / `user_message` |
| Session ID exposed? | Y |
| Agent ID exposed? | N |
| Context provenance exposed? | N (optional `agent_message` text only) |
| Subagent/delegation exposed? | Task tool visible as tool name |
| Bypass paths? | Matcher miss; fail-open unless `failClosed`; race/empty-stdin reports |

### beforeShellExecution — **canonical enforcement**

| Question | Answer |
|---|---|
| Observable before execution? | Y |
| Arguments visible? | Shell `command`, cwd, sandbox flags (per docs/examples) |
| Can execution be denied? | Y **`deny`**; `ask` unreliable (forum: only deny works consistently) |
| Can result be modified? | N (gate, not rewrite — use preToolUse for rewrite) |
| Does denial return to the agent? | Y `agent_message` / `user_message` |
| Session ID exposed? | Y |
| Agent ID exposed? | N |
| Context provenance exposed? | N |
| Subagent/delegation exposed? | N |
| Bypass paths? | See `cursor-blind-spots.md` (sandbox ask bugs, race, non-shell tools) |

### afterShellExecution

| Question | Answer |
|---|---|
| Observable before execution? | N (after) |
| Arguments visible? | Command + output fields per docs |
| Can execution be denied? | N |
| Can result be modified? | N |
| Does denial return to the agent? | N/A |
| Session / agent / provenance / subagent | Session Y; agent N; provenance N; subagent N |
| Bypass paths? | Only fires if command ran |

### beforeReadFile

| Question | Answer |
|---|---|
| Observable before execution? | Y (before content is given to the model) |
| Arguments visible? | `file_path`, **`content` (full)**, attachments |
| Can execution be denied? | Y `permission: "deny"` |
| Can result be modified? | N |
| Does denial return to the agent? | `user_message`; content not sent to model if denied |
| Session ID exposed? | Y |
| Agent ID exposed? | N |
| Context provenance exposed? | Path + attachments; content present in hook stdin |
| Subagent/delegation exposed? | N |
| Bypass paths? | Tab read uses different hook; shell `cat` bypasses this hook; **content already in hook process** |

### afterFileEdit

| Question | Answer |
|---|---|
| Observable before execution? | N (after edit) |
| Arguments visible? | `file_path`, edits |
| Can execution be denied? | N |
| Can result be modified? | Formatters may post-process (not Harn.x Phase 4A) |
| Denial to agent / IDs | N/A / session Y |

### beforeMCPExecution / afterMCPExecution

| Question | Answer |
|---|---|
| Observable before execution? | before: Y · after: N |
| Arguments visible? | Tool name + params |
| Can execution be denied? | before: Y (`deny`/`ask`/`allow`); use deny + `failClosed` for security |
| Can result be modified? | after: limited (e.g. MCP output update on related post hooks) |
| Does denial return to the agent? | Y messages |
| Session / agent / provenance / subagent | Session Y; agent N; MCP trust is Harn.x-derived; subagent N |
| Bypass paths? | Cloud deferred MCP hooks historically; non-MCP tools |

### subagentStart / subagentStop

| Question | Answer |
|---|---|
| Observable before execution? | Start: Y · Stop: after |
| Arguments visible? | `subagent_id`, type, `parent_conversation_id` |
| Can execution be denied? | Schema allows deny on start; **Phase 4A treats as observation-only** until side-effect proof |
| Can result be modified? | Stop: `followup_message` (must not script Action B) |
| Does denial return to the agent? | Unproven for reliable block |
| Session ID exposed? | Y (parent conversation) |
| Agent ID exposed? | P — `subagent_id` only |
| Context provenance exposed? | N |
| Subagent/delegation exposed? | Y |
| Bypass paths? | Claim without runtime proof is forbidden |

### stop / afterAgentResponse / afterAgentThought / preCompact

Observation / automation hooks. Phase 4A records when useful; **never** uses `followup_message` to manufacture post-block autonomy.

## Denial semantics (Cursor)

- Exit `0` + JSON: apply output  
- Exit `2`: block (≡ deny)  
- Other exits: **fail-open** unless `failClosed: true`  
- Prefer `permission: "deny"` over `ask` for security proofs  

## Marketplace packaging

Documented enterprise/team cloud distribution and Customize plugins exist.
**Phase 4A does not submit to Marketplace** and does not invent a fake install CLI.

## Adapter placement

```text
packages/harnesssec/src/adapters/cursor/
```

No `if (harness === "cursor")` inside behavioral detection / normalizer / policy rule logic.
