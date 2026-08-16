# Phase 1 Findings

## Thesis under test

> There is security-relevant semantic information inside the agent harness that existing endpoint, runtime, network, identity, and cloud security layers cannot reliably reconstruct — and HarnessSec can use that information to detect or prevent dangerous autonomous behavior.

## Verdict

**Thesis holds for the verified DeepSeek Harness surface.**

We demonstrated (see `harnesssec demo` / tests):

| Criterion | Result |
|---|---|
| Agent-aware session recording | Yes |
| Tool intent before execution | Yes (`tools/pre-execute`) |
| Context provenance | Yes (`MessageSource` + untrusted tool results) |
| MCP provenance | Yes (`mcp__server__tool` naming) |
| Agent lineage | Yes (`subagent/start` wired; demo uses single agent) |
| Capability available vs used | Yes (snapshot + used set) |
| Causal event graph | Yes (`links.*` + `graph.why`) |
| Pre-execution policy | Yes |
| Action blocking | Yes (`PreToolDecision.deny` — Phase 0 verified) |
| Post-block agent behavior | Yes (`policy.aftermath`) |
| Session replay | Yes (`harnesssec replay`) |

At least one capability is hard to reconstruct from OS/network alone:

> **Blocked `bash` / `cat ~/.ssh/id_rsa` after untrusted README context — no process is spawned; the causal chain (objective → untrusted context → tool intent → BLOCK) exists only in harness semantics.**

## What we did **not** prove

- Live attach inside a running `dsh` process in CI (adapter is written to the verified Cordis seams; install via `dsh plugin add`)
- OS-level file/network telemetry (intentionally out of scope)
- Peer plugin admission control
- Perfect taint tracking (only defensible provenance)
- That every bypass path is closed (direct `ctx.shell`, shell children, external subagents remain)

## Differentiator captured

```text
HARNESS_NATIVE:
  agent identity, session, tool intent, context source/trust,
  MCP tool naming, sub-agent edges, policy decision, aftermath

NOT OUR LAYER:
  process.exec, file.read, network.connect
```

## Recommendation

Proceed to a **thin live integration test** against DeepSeek Harness (`dsh plugin add` + one headless turn) before expanding rules. Do not start eBPF / dashboards.
