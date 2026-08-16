# Phase 2.1 — Final Portability Validation

**Status: COMPLETE** (validated by green tests; not by code presence alone)

Date: 2026-08-16  
Repo: https://github.com/inaor/Harn.x

---

## Recommendation (architecture-contract vocabulary)

```text
PASS
```

The Harn.x security abstraction is portable across DeepSeek DSH and OpenHands with:

- same core recorder / policy / `defaultRules`
- vendor mapping confined to adapters
- real OpenHands UserPromptSubmit → `context.introduced` provenance (no synthetic seed in the live proof)

Phase 3 behavioral detection language must **not** start until product owner explicitly opens it.

---

## What Phase 2.1 closed

| Gap | Resolution |
|---|---|
| Live test used `openhands-seed` | Removed from canonical live path |
| Untrusted context not from OpenHands | Wired `UserPromptSubmit` hook on live Conversation |
| Provenance chain weak (credential-only block) | BLOCK uses `untrusted-context-sensitive-tool` (curl after untrusted) |
| `harness.name` closed union | Extensible `export type HarnessName = string` (+ convenience constants) |
| Independent review missing | GitHub Guardian workflow after CI |

`openhands-seed` remains a **developer/demo utility only**.

---

## End-to-end proof (OpenHands)

```text
user message with <UNTRUSTED_CONTENT>
        ↓
OpenHands UserPromptSubmit hook → harnesssec openhands-hook
        ↓
normalized context.introduced (trust=untrusted, source_hook=openhands:UserPromptSubmit)
        ↓
model terminal intent (curl + touch proof)
        ↓
OpenHands PreToolUse → same Harn.x defaultRules
        ↓
BLOCK (untrusted-context-sensitive-tool)
        ↓
UserRejectObservation
        ↓
/tmp/harnx-openhands-proof ABSENT
```

ALLOW control: benign `touch /tmp/harnx-openhands-allowed` succeeds under the same untrusted context.

Bypass: `execute_tool` still creates `/tmp/harnx-openhands-bypass-proof` (documented).

---

## Test evidence (observed)

```sh
cd packages/harnesssec
npm ci && npm run build && npm test && npm run test:integration
```

```text
✔ portability regression: same policy blocks DSH bash and OpenHands terminal
… (20 unit tests pass)

✔ LIVE: BLOCK / ALLOW / bypass / agent-loop          (DeepSeek)
✔ LIVE OpenHands: BLOCK / ALLOW / bypass via PreToolUse adapter
  BLOCK.userprompt_provenance === true
  BLOCK.block_rules includes untrusted-context-sensitive-tool
  BLOCK.proof_exists === false
  ALLOW.proof_exists === true
ℹ integration pass 5 / fail 0
```

---

## Core change (justified)

| Change | Why universal | DeepSeek impact |
|---|---|---|
| `export type HarnessName = string` | Avoid per-adapter schema edits | Defaults remain `deepseek-dsh` |
| Policy events copy `event.harness` | Preserve producer identity | DSH events still branded correctly |

No rule rewrites. No Phase 3 detection language.

---

## GitHub Guardian

| Property | Implementation |
|---|---|
| Trigger | `workflow_run` after workflow `CI` completes on a `pull_request` |
| Merge gate | Deterministic **CI** remains required; Guardian does not auto-merge |
| Trust boundary | Checks out **default branch** only; reviews PR diff via API; never executes PR code |
| Secrets | `GITHUB_TOKEN` only (`contents:read`, `actions:read`, `pull-requests:write`) — no write-capable custom secrets for untrusted code |
| Output | PR review comment: `PASS` / `REQUEST_CHANGES` / `BLOCK` |
| Contract | Reads `docs/architecture-contract.md` |
| Checks | vendor-in-core, causality, secret persistence, enforcement claims, bypass/docs, policy+tests, schema drift, **HarnessName docs/code mismatch**, premature Phase 3 |
| Self-test | `.github/guardian/self-test.mjs` + fixture `fixtures/harness-name-mismatch.json` (docs claim open + closed union → REQUEST_CHANGES/BLOCK) |

Workflow: `.github/workflows/guardian.yml`  
Script: `.github/guardian/review.mjs`

---

## Deliverables checklist

- [x] Real OpenHands provenance integration test (UserPromptSubmit)
- [x] Green unit + integration CI matrix
- [x] GitHub Guardian workflow/config
- [x] Guardian HarnessName docs/code mismatch self-test
- [x] This document

**Do not start Phase 3 from this document alone.**
