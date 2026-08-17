# Cursor Blind Spots (Phase 4A)

Architectural bypasses and limitations from **public docs**, Cursor forum reports,
and adapter design. Do **not** claim complete Cursor control.

## Explicit Phase 4A limitations (required)

### 1. Canonical enforcement is shell-only

Required Proof 1 uses **`beforeShellExecution`** with:

- `failClosed: true`
- `permission: "deny"`

Do **not** treat `ask` as a security control for the canonical test. Cursor
maintainers have stated that **`ask` is not reliably enforced** (only `deny`
works consistently across shell paths).

### 2. subagentStart is observation-only

Harn.x may record `subagent.spawned` when Cursor exposes `subagent_id` /
parent conversation fields.

**Do not claim** reliable subagent blocking from a hook `permission` response
alone. A future blocking claim requires **side-effect / runtime evidence** that
the subagent did not run.

### 3. Minimize hook payload persistence (especially beforeReadFile)

Cursor's `beforeReadFile` input may include the **full file `content`** in the
hook process stdin. Harn.x must:

- **not persist full file contents by default**
- prefer path, metadata, trust/provenance, and content **hashes**
- persist **redacted excerpts only** when a security primitive requires them
  (e.g. short untrusted-marker evidence)

Even when Harn.x denies the read to the model, the hook process may already
have seen bytes — lab fixtures only; never point hooks at real secrets.

## Additional blind spots

| Surface | Why Harn.x may be blind / weak |
|---|---|
| Default fail-open | Hook crash/timeout/invalid JSON allows the action unless `failClosed: true` |
| Tab completions | `beforeTabFileRead` / `afterTabFileEdit` — separate from Agent proof |
| Non-shell tools | `Read` / `Write` / `Grep` do not traverse `beforeShellExecution` |
| Path-scoped Grep | Explicit `file_path` on Grep is normalized like Read when taxonomy matches; **directory/recursive** Grep without a sensitive path remains non-deterministic |
| Broad tool output | `git diff` / `grep -R` — see `docs/sensitive-output-control.md` (no default block) |
| Parallel preToolUse | Concurrent hook processes share a session file; recorder merge+lock required to avoid dropped `tool.requested` rows |
| preToolUse Shell | Telemetry recorded; **enforcement** remains `beforeShellExecution` (`failClosed`) — documented in adapter notes |
| Policy gap on Read | Existing `credential-path-in-shell-args` matches **shell** args; path-scoped Read/Grep use `sensitive-resource-read` |
| Shell vs Read | Agent can `cat` sensitive path via Shell (gated) or Read/Grep (path-scoped sensitive-resource-read) |
| Remote workspaces | Reports of empty stdin to hooks → no inspect/deny payload |
| Fast-hook race | Forum: deny JSON dropped if process exits before stdout is read |
| Sandboxed Agent shell | Historical bugs around permission gating on `sandbox: true` paths |
| Cloud agents | Partial hook set; user `~/.cursor` hooks unavailable; sessionStart deferred |
| CLI vs IDE | Cursor CLI historically incomplete vs IDE Agent hooks |
| Model credentials | Never visible to Harn.x (by design) — also means no model-side attestation |
| Transcript files | `transcript_path` may exist; Harn.x does not scrape private Cursor internals |
| MCP in cloud | Historically deferred while read-only cloud turns run without hooks |
| `updated_input` races | Rewrite via `preToolUse` is not the canonical deny proof |
| stop follow-ups | `followup_message` could script continuation — **forbidden** for autonomy claims |

## What we will not do

- Reverse engineer private Cursor binaries  
- Patch Cursor  
- Intercept Cursor network traffic  
- Require Cursor model API keys  
- Present synthetic Cursor events as live evidence  
