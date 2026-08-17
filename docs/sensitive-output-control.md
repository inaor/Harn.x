# Sensitive Output / Tool Result Control

**Status:** research / design only — **no production policy** to block broad `git diff`.  
**Phase:** 4A follow-up (post Proof B2 PARTIAL).  
**Do not confuse with:** deterministic sensitive-resource content access (`READ_SENSITIVE_FILE`).

## Problem class

Some agent actions can return sensitive file contents **without** naming a
sensitive resource in the pre-execution request:

| Request | Deterministic sensitive target? |
|---------|----------------------------------|
| `Read(file_path=.env)` | Yes |
| `Grep(pattern=".", file_path=.env)` | Yes |
| `cat .env` | Yes (strong remap) |
| `git diff` (no path args) | **No** — output set unknown until run |
| `grep -R pattern .` | **No** — recursive scope |
| Arbitrary scripts | **No** |

Proof B2 showed production **Read** enforcement worked, while a broad
`git diff` was **allowed** and may have contributed to model-visible
identity markers. That is an **output/effect visibility** problem, not a
normalization bug.

## What Cursor exposes pre-execution

For Agent Shell tools (documented hooks):

- `beforeShellExecution` — command string, cwd, metadata; **not** predicted
  stdout/stderr or the set of files the command will touch.
- `preToolUse` — tool name + `tool_input` (for Shell, typically the command).
- No documented Cursor field that lists “files this command will emit” for
  arbitrary `git diff` / scripts.

Therefore Harn.x **cannot** deterministically label `git diff` as
`READ_SENSITIVE_FILE` for a specific path when the request does not name one.

## Can Harn.x know which content will reach the model?

| Boundary | Timing | Can filter body before model context? |
|----------|--------|----------------------------------------|
| `beforeShellExecution` / `preToolUse` | Pre-exec | Policy can **deny** the whole tool; cannot rewrite unknown future stdout |
| `afterShellExecution` / `postToolUse` | Post-exec | Observes that a tool finished; **output already produced**; typically **too late** to keep bytes out of model context if Cursor already attached results |
| `beforeReadFile` | Pre-read | Path (+ optional content in hook stdin); gateable with `failClosed` — **not** a general tool-result filter |

**Conclusion:** Without a proven **pre-model interception** hook that can
inspect or redact **tool results** before they become model messages,
blocking generic `git diff` by default is unsafe theater:

- False sense of coverage for other broad commands.
- Breaks legitimate developer workflows.
- Still misses scripts/`grep -R`/editor buffers/etc.

## Unresolved work (do not implement until proven)

1. Confirm whether Cursor exposes any hook that receives **tool output**
   and can **deny or redact** it **before** model turn assembly.
2. If yes: design vendor-neutral `SENSITIVE_OUTPUT` / result-control
   events (observed output fingerprints only; never persist raw secrets).
3. If no: keep documenting this as a harness blind spot; rely on
   deterministic path-scoped access policy + operator awareness.

## Policy stance (current)

- **Do** block deterministic content access to sensitive resources
  (Read / path-scoped Grep / simple `cat` / etc.) via
  `sensitive-resource-read`.
- **Do not** classify bare `git diff` as `READ_SENSITIVE_FILE`.
- **Do not** add Cursor-only branches to “fix” output leakage.

## Related

- Historical Proof B2 = **PARTIAL** (Read blocked; alternate content paths remained).
- Follow-up acceptance (after Grep closure): Proof B3 — explicit Grep on
  sensitive fixtures must BLOCK under production rules; broad `git diff`
  remains documented unresolved until a safe pre-model boundary exists.
