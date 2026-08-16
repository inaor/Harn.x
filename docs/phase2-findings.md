# Phase 2 Findings — OpenHands Portability

## Phase 2 recommendation (contract vocabulary)

```text
PASS
```

The Harn.x security abstraction is portable enough to proceed to Phase 3 planning **after** this review’s blockers are landed (gitignore fix + fail-closed hook exits are included in this tree).

Not optimized for PASS: several HIGH/MEDIUM issues remain as honesty items, but they do not require core redesign.

Alternative considered: **PARTIAL** — only if `openhands-seed` were treated as the sole untrusted-context path with no adapter mapping for OpenHands-native untrusted markers. Rejected because (a) UserPromptSubmit mapping exists, (b) live BLOCK uses the same `defaultRules` against real `terminal` PreToolUse, (c) DeepSeek regression holds.

---

## Guardian review (adversarial)

```text
VERDICT: REQUEST CHANGES → cleared after BLOCKER fixes in-tree

ARCHITECTURE:
  Adapter-only OpenHands integration. Core change limited to harness.name union.
  Layers match contract (adapter → events → policy). No Phase 3 DSL shipped.

SECURITY:
  Live PreToolUse BLOCK proven (proof file absent). ALLOW control proven.
  Blind spot execute_tool proven + documented. Persist redaction path unchanged.
  Hook fail-closed on parse/internal error (exit 2) required by invariant 8.

PORTABILITY:
  Same defaultRules; terminal→bash mapping in adapter; DeepSeek live tests still pass.

EVIDENCE:
  npm test (19) + npm run test:integration (5: 4 DSH + 1 OpenHands live)
  Side effects: /tmp/harnx-openhands-proof absent; /tmp/harnx-openhands-allowed present
  Bypass: /tmp/harnx-openhands-bypass-proof present via execute_tool

FINDINGS:
  BLOCKER  .gitignore previously matched **/openhands/ and excluded
           packages/harnesssec/src/adapters/openhands/ from git — FIXED (root-anchored)
  HIGH     openhands-hook used exit 1 on error → OpenHands fail-open — FIXED (exit 2 deny)
  MEDIUM   Live demo seeds untrusted context via openhands-seed in addition to
           message markers; UserPromptSubmit hook not wired in live script
  MEDIUM   browser*→web_fetch synonym is a coarse semantic map (adapter-local)
  LOW      harness.name schema widened — justified universal primitive
  INFO     Turn metadata is adapter session sidecar (OpenHands has no DSH turn)

PHASE IMPACT:
  Phase 2 can be considered COMPLETE for portability gate once this tree is committed.
  Phase 3 behavioral language remains FORBIDDEN until explicit start.

NEXT ACTION:
  1. Commit/push including adapters/openhands (gitignore fix critical)
  2. Optional: wire UserPromptSubmit in live harness for pure OH provenance path
  3. Do not start Phase 3 until product owner accepts this PASS
```

---

## Final question (evidence)

> Is Harn.x a DeepSeek security plugin, or a portable security abstraction?

**Portable abstraction on the pre-exec tool-intent path** across Cordis `tools/pre-execute` and OpenHands PreToolUse — with explicit incomplete coverage of capability seams (`ctx.shell`, `execute_tool`, bash/file APIs).

---

## Stress test answers

| # | Answer |
|---|---|
| Core files changed | 1 semantic: `events/schema.ts` (`harness.name`) |
| Why | Universal harness identity; DeepSeek still maps |
| Rules changed | 0 |
| Schema change | Minimal union only |
| DeepSeek tests | Pass unchanged |
| Same policy both | Yes (`defaultRules`) |
| Vendor in core | No |
| Cannot normalize cleanly | confirmation/security_analyzer planes; `/api/bash`; prompt-injected skills; OH turn model |

---

## Contracts adopted

- `docs/architecture-contract.md`
- `.cursor/rules/harnx-architecture.mdc`
- `.cursor/rules/harnx-guardian.mdc`

**Not started:** Phase 3 behavioral detection language.
