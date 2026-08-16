# HarnessSec Security Primitives

Classification of Phase 1 signals relative to existing security products.

```text
HARNESS_NATIVE  — only reconstructible from harness semantics
RUNTIME_GENERIC — already covered by EDR / eBPF / network / CNAPP
DERIVED         — inferred enrichment, not a native harness fact
UNKNOWN         — Phase 0 did not verify a reliable source
```

---

## Primitive catalog

| Primitive | Class | Source | Notes |
|---|---|---|---|
| `session.started` / `session.ended` | HARNESS_NATIVE | `session/created`, `session/disposed` | |
| `agent.started` / `agent.ended` | HARNESS_NATIVE | `agent/created`, `agent/disposed` | |
| `agent.step.admitted` | HARNESS_NATIVE | `agent/pre-step` / turn+step session events | Turn boundaries |
| `objective.captured` | DERIVED | first user message | Best-effort |
| `context.introduced` | HARNESS_NATIVE | `user/message`, untrusted `tool/result` | **Turn-scoped** |
| `context.trust` | DERIVED | policy over source kind | Not malware verdict |
| `tool.requested` | HARNESS_NATIVE | `tools/pre-execute` | Intent before OS |
| `tool.denied` | HARNESS_NATIVE | pre-execute deny | Body skipped — live-proven |
| `tool.completed` | HARNESS_NATIVE | `tools/result` | |
| `shell.command_requested` | HARNESS_NATIVE | bash/pwsh tool args | Outer command only |
| `mcp.tool_requested` | HARNESS_NATIVE | `mcp__*` tool names | |
| `mcp.trust` | HARNESS_NATIVE | operator registry + observe | trusted / untrusted / unknown — **not** “unknown because MCP” |
| `subagent.spawned` / `ended` | HARNESS_NATIVE | `subagent/start` / `end` | In-process |
| `capability.snapshot` / `used` | HARNESS_NATIVE | schemas + tool requests | Available vs used |
| `policy.decision` | HARNESS_NATIVE | Harn.x engine | |
| `policy.aftermath` | HARNESS_NATIVE | next tool after BLOCK | **correlated_with**, not caused_by |
| `process.exec` | RUNTIME_GENERIC | — | Out of scope |
| `file.read` (OS) | RUNTIME_GENERIC | — | Out of scope |
| `network.connect` | RUNTIME_GENERIC | — | Out of scope |
| `credential.access` | DERIVED | sensitive tokens in **tool args** | Redacted on disk |
| Direct `ctx.shell.run` | UNKNOWN to Harn.x | blind spot | Confirmed — see blind-spots.md |

---

## Link honesty

| Link | When allowed |
|---|---|
| `caused_by` | Only defensible causality (rare) |
| `result_of` | tool.denied/completed ← tool.requested |
| `policy_decision_for` | policy ← tool.requested |
| `candidate_context_source` | Same-turn untrusted context |
| `correlated_with` | Temporal / weak association |

Do **not** emit `caused_by` for “context then tool in the same session.”

---

## Differentiator test

Passing (live):

- `tool.denied` before bash body → `/tmp/harnx-proof` absent
- Same-turn untrusted context correlation without sticky session taint

Failing / out of scope:

- Observing `ctx.shell.run` bypass
- Claiming OS `file.read` / `network.connect`
