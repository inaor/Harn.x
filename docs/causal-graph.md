# Causal Graph

HarnessSec stores a **graph of harness events**, not only a flat log.

Implementation: `packages/harnesssec/src/graph/causal.ts`

---

## Purpose

Given one suspicious action, reconstruct:

```text
WHO (agent)
WHY (objective + context provenance)
WHAT WAS INTENDED (tool request)
WHAT INFLUENCED IT (context_source link)
WHAT POLICY DID (policy_decision_for)
WHAT HAPPENED NEXT (policy.aftermath)
```

---

## Edge relations

| Relation | Meaning |
|---|---|
| `caused_by` | Upstream event that led here |
| `parent_event` | Immediate parent in the same flow |
| `parent_agent` | Creating / owning agent |
| `delegated_by` | Sub-agent spawn parent |
| `context_source` | Untrusted/trusted context event that scopes this action |
| `tool_source` | Parent `tool.requested` for shell/mcp specialization |
| `result_of` | Completion/deny of a prior request |
| `policy_decision_for` | Policy event evaluates this request |

---

## Walk API

```text
recorder.graph.why(eventId) → ordered ancestor chain
recorder.graph.render(sessionId) → text graph
```

---

## Demo chain (attack-demo)

```text
objective.captured
        │
        ▼
context.introduced  (user, trusted)
        │
        ▼
tool.requested read README.md
        │
        ▼
context.introduced  (README.md, UNTRUSTED)  ← context_source
        │
        ▼
tool.requested bash cat ~/.ssh/id_rsa
        │
        ▼
policy.decision BLOCK
        │
        ▼
tool.denied   (body never ran)
        │
        ▼
tool.requested read /etc/shadow
        │
        ▼
policy.aftermath   (alternate route after block)
```

An EDR may see nothing for the blocked bash call. The graph still explains **why** the agent attempted it.
