# Harn.x — Architecture Contract & Development Direction

Source of truth for product position, phase gates, and security uniqueness.
See also: `.cursor/rules/harnx-architecture.mdc`, `.cursor/rules/harnx-guardian.mdc`.

## North Star

Harn.x is an open detection and response layer for autonomous agent behavior.

Harn.x is **not** an EDR, eBPF monitor, MCP gateway, network proxy, identity product, CNAPP, AI firewall, or standalone SOC.

Core hypothesis:

> Security-relevant information exists inside agent harnesses that endpoint, runtime, network, identity, and cloud security layers cannot reliably reconstruct after execution.

Every major feature must strengthen or falsify this hypothesis.

## Layers

```text
1. HARNESS ADAPTERS  →  2. NORMALIZED EVENT MODEL  →  3. BEHAVIOR GRAPH
                     →  4. DETECTION / POLICY      →  5. RESPONSE + EXPORT
```

Vendor-specific details stay in adapters. Core stays vendor-neutral.

## Security invariants (never regress)

1. Raw secrets never persisted unredacted.
2. Policy may inspect raw in-memory telemetry before persist redaction.
3. No unsupported causal claims.
4. Vendor-specific semantics stay inside adapters.
5. Enforcement claims require pre-execution proof.
6. Every adapter documents bypass paths.
7. Never claim complete execution coverage unless proven.
8. A failed security sensor must not silently weaken protection.
9. Existing adapters must keep passing when a new adapter is added.
10. Documentation must reflect code, not intention.

## Phase gates

| Phase | Gate |
|---|---|
| 1 DeepSeek | Live pre-exec BLOCK + ALLOW + documented bypass |
| 2 OpenHands | Same core/rules; different adapter; portability proven or fail honestly |
| 3 Behavioral model | Only after Phase 2 PASS |
| 4 Third harness | Materially different ecosystem |
| 5 Distribution | Only after abstraction is credible |

**Do not start Phase 3 until Phase 2 is reviewed PASS.**

## Phase 2 verdict vocabulary

```text
PASS     — abstraction portable enough to proceed
FAIL     — overly coupled to DeepSeek; stop and redesign
PARTIAL  — some primitives generalize; redesign required before Phase 3
```

Optimize for truth, not PASS.
