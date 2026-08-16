# Phase 1 Findings (updated after live validation)

## Verdict

**Phase 1 COMPLETE.**

Live DeepSeek Harness execution demonstrated:

- BLOCK before tool body (`/tmp/harnx-proof` absent)
- ALLOW control (`/tmp/harnx-allow-ok` present)
- Agent-loop model → bash blocked
- Bypass via `ctx.shell` documented as a blind spot

Architecture-review + Phase 1.5b fixes (persist-only redaction with raw in-memory telemetry, no sticky provenance, MCP trust matrix, bash/pwsh not unconditionally sensitive) are covered by `tests/phase15b-regression.test.ts` + `tests/architecture-regression.test.ts` and green CI (`npm ci` / `build` / `test` / `test:integration`).

See [`phase1-live-validation.md`](./phase1-live-validation.md) and [`blind-spots.md`](./blind-spots.md).

---

## Thesis

> There is security-relevant semantic information inside the agent harness that existing endpoint/runtime/network layers cannot reliably reconstruct — and Harn.x can use it to detect or prevent dangerous autonomous behavior.

**Holds** for tool-mediated paths. **Does not hold** for direct capability seams (`ctx.shell`, etc.).

---

## What changed since the demo-only milestone

| Item | Before | After |
|---|---|---|
| Execution proof | Simulated demo events | Real `dsh-tools` + bash + agent-loop |
| Side-effect proof | Claimed | `/tmp/harnx-proof` absent after BLOCK |
| Causality links | Over-claimed `caused_by` / sticky context | `candidate_context_source` / `correlated_with`; turn-scoped only (`latestUntrusted` removed) |
| MCP | Alert on all `mcp__*` / unknown conflated | trusted → allow; unknown → allow/log; untrusted → alert (`event.mcp.trust`) |
| Shell sensitivity | bash/pwsh treated as inherently sensitive (`SENSITIVE_TOOLS`) | No unconditional bash/pwsh; command semantics or explicit `sensitivity=high`; `git status` / `npm test` ALLOW under untrusted |
| Secrets | Persisted raw / redacted before policy | `record()` keeps raw; policy inspects secrets in memory; only `persist()` writes redacted clone |
| CI | None / incomplete | `npm ci` + build + unit + `test:integration` (clean checkout) |
| Regression | Scattered | `phase15b-regression.test.ts` (shell + raw telemetry) + `architecture-regression.test.ts` |

---

## Differentiator still unique to harness

Blocked bash with credential path in args:

- EDR sees **no process**
- Harn.x records agent, session, tool intent, policy decision, optional same-turn untrusted context correlation

---

## Do not expand into

Dashboard, eBPF, more harness adapters, or large rule packs — until live attach via `dsh plugin add` is exercised in a production-like profile if needed.
