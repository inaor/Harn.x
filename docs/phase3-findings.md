# Phase 3 Findings — Stateful Behavioral Detection

## Verdict: PASS (with documented PARTIAL live OH lineage)

```text
VERDICT: PASS

ARCHITECTURE:
  BehavioralEngine is a parallel consumer of normalized events (not dependent on
  FlightRecorder / persistence). Policy and recorder remain separate.
  BlockedActionMemory (not "intent"). Normalization levels exact|strong|unknown.
  CapabilityTracker: available only from snapshots; used from tool requests.
  No Harness #3, no YAML DSL, no dashboard, no eBPF.

SECURITY:
  Circumvention detections require exact/strong deterministic equivalence only.
  Original action evidence preserved on NormalizedAction.original.
  No caused_by for behavioral correlation.
  behavior.detection cannot recursively trigger itself (guard + regression test).

PORTABILITY (detector):
  Same BehavioralEngine for harness.name deepseek-dsh and openhands.
  Zero harness branches / FlightRecorder imports in src/behavior/.

TELEMETRY (live adapter):
  OpenHands delegated lineage emission remains PARTIAL (no subagent.* hooks).
  Detector-portable ≠ live OH coverage.

EVIDENCE:
  packages/harnesssec/tests/phase3-behavior.test.ts
  docs/behavioral-model.md
  docs/behavioral-detections.md

FINDINGS:
  PASS     Multi-event stateful circumvention detections
  PASS     Detector portability across two harness names
  PASS     FP + aggressive normalization negatives
  PASS     Capability available ≠ used
  PASS     Detection recursion regression
  PARTIAL  Live OpenHands lineage telemetry
  INFO     Privilege expansion is a medium signal, not auto-malice

PHASE IMPACT:
  Phase 3 behavioral primitive established.
```

## Detector portability vs live telemetry (explicit)

| | Detector portability | Live OpenHands lineage |
|---|---|---|
| Delegated circumvention | PASS (normalized events) | PARTIAL (adapter gap) |

## Final question

> Can Harn.x identify and respond to autonomous security behavior rather than merely inspect individual agent actions?

**Yes, for demonstrated autonomous policy circumvention** (alternate capability + delegated retry with explicit lineage) via stateful detectors on normalized events. Per-request policy remains. Live OpenHands child-agent telemetry is still incomplete — detector portability is not claimed as live OH coverage.
