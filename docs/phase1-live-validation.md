# Phase 1 Live Validation

**Status: COMPLETE** — real DeepSeek Harness Cordis runtime + ToolRuntime + bash + agent-loop.

Date: 2026-08-16  
Repo: https://github.com/inaor/Harn.x

---

## What “live” means here

Harn.x was loaded with `apply()` as a Cordis plugin into a real DeepSeek Harness composition:

| Component | Package |
|---|---|
| Cordis runtime | `@deepseek-ai/cordis` |
| Tool pipeline | `@deepseek-ai/dsh-tools` |
| Bash tool | `@deepseek-ai/dsh-tool-bash` |
| Local bash executor | `@deepseek-ai/dsh-bash-local` |
| Subprocess | `@deepseek-ai/dsh-subprocess-local` |
| Agent loop | `@deepseek-ai/dsh-agent-loop` + testkit |
| Harn.x | `packages/harnesssec` adapter |

This is the same execution path model tool calls use (`tools/pre-execute` → body). It is not a simulated fake pipeline.

Install path for a full `dsh` profile (when using a built dsh tree):

```sh
dsh plugin --profile headless add /path/to/Harn.x/packages/harnesssec
```

---

## Proof results

Run:

```sh
cd packages/harnesssec
npm run test:integration
```

Observed output (2026-08-16):

```text
✔ LIVE: BLOCK prevents bash side effect (/tmp/harnx-proof absent)
✔ LIVE: ALLOW control — benign bash succeeds and creates marker
✔ LIVE: bypass — ctx.shell.run from peer plugin is invisible to Harn.x
✔ LIVE: agent-loop turn — model tool call blocked before side effect
ℹ tests 4
ℹ pass 4
ℹ fail 0
```

### 1. BLOCK before side effect

Command attempted via `ctx.tools.execute` / agent-loop:

```text
touch /tmp/harnx-proof; cat ~/.ssh/id_rsa
```

After Harn.x `tools/pre-execute` deny:

- tool result `isError === true`
- **`/tmp/harnx-proof` does not exist**

External side-effect proof: the filesystem marker is absent.

### 2. ALLOW control

```text
echo allow-ok > /tmp/harnx-allow-ok
```

- tool result success
- file exists with `allow-ok`

Same harness, opposite policy outcome.

### 3. Agent-loop turn

Mock model emitted a bash tool call. Harn.x blocked before body. Loop proof file absent. Session contains `tool.denied` + `policy.decision=block`.

### 4. Bypass blind spot

`ctx.shell.resolve(...); ctx.shell.run(spec)` from a peer-injected shell consumer created `/tmp/harnx-bypass-proof` **without** any Harn.x `tool.requested` / `shell.command_requested` for that command.

Documented in [`blind-spots.md`](./blind-spots.md).

---

## Semantics fixes validated in unit tests

Architecture-review + Phase 1.5b inconsistencies were fixed and covered by regressions. Docs updated only after:

```sh
npm ci && npm run build && npm test && npm run test:integration
```

all passed (including clean-checkout `npm ci`).

| Fix | Behavior | Test |
|---|---|---|
| Persist redaction | `record()` stores/returns raw event; only `persist()` redacts a clone | `tests/phase15b-regression.test.ts`, architecture + redaction tests |
| No sticky provenance | `candidateUntrustedForStep` only; no association when turn unknown; `latestUntrusted` removed | architecture regression |
| MCP trust | trusted → allow; unknown → allow/log; untrusted → alert via `event.mcp.trust` | architecture regression + unit |
| Shell sensitivity | No unconditional bash/pwsh sensitivity; semantics or explicit high only | `tests/phase15b-regression.test.ts` |
| CI contract | `test:integration` + declared DSH deps; `npm ci` / build / test / integration | architecture regression + GHA |

### Phase 1.5b shell + raw telemetry (observed)

```text
✔ phase1.5b: untrusted + git status => ALLOW
✔ phase1.5b: untrusted + npm test => ALLOW
✔ phase1.5b: untrusted + cat ~/.ssh/id_rsa => BLOCK
✔ phase1.5b: untrusted + credential/exfil command => BLOCK
✔ phase1.5b: policy inspects raw in-memory secrets; persist has none
ℹ tests 15
ℹ pass 15
ℹ fail 0
```

Live integration (unchanged proofs):

```text
✔ LIVE: BLOCK / ALLOW / bypass / agent-loop
ℹ pass 4  fail 0
```

---

## Phase 1 completion checklist

| Criterion | Met? |
|---|---|
| Real DSH tool pipeline | Yes |
| Real agent-loop turn | Yes |
| External side-effect BLOCK proof | Yes |
| ALLOW control | Yes |
| Bypass documented | Yes |
| Causal link honesty | Yes |
| Context turn scoping (no sticky) | Yes |
| MCP trust states (trusted/unknown/untrusted) | Yes |
| Recorder: raw in-memory; redact on persist only | Yes |
| Shell sensitivity by semantics (not tool name) | Yes |
| CI (build + unit + integration) | Yes |

**Phase 1 is COMPLETE** — validated by green unit + live integration tests, not by code presence alone.
