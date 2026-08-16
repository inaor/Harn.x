# HarnessSec

Open-source **harness-native** security instrumentation for AI agent harnesses.

> Models think. Harnesses act. We secure the execution layer.

Not an EDR. Not eBPF. Not a network proxy.

**Flight recorder + pre-execution policy for autonomous agents.**

## Status

| Phase | Status |
|---|---|
| 0 — DeepSeek choke-point map | Complete — [`docs/deepseek-harness-architecture.md`](docs/deepseek-harness-architecture.md) |
| 1 — Harness flight recorder | Complete — see below |

## Quick demo

```sh
cd packages/harnesssec
npm install
npm run demo
```

## CLI

```text
harnesssec demo
harnesssec sessions
harnesssec replay attack-demo
harnesssec graph attack-demo
harnesssec detections
harnesssec attach dsh
```

## Docs

- [`docs/phase1-capabilities.md`](docs/phase1-capabilities.md)
- [`docs/security-primitives.md`](docs/security-primitives.md)
- [`docs/event-schema.md`](docs/event-schema.md)
- [`docs/causal-graph.md`](docs/causal-graph.md)
- [`docs/phase1-findings.md`](docs/phase1-findings.md)

## DeepSeek attach

```text
dsh plugin --profile web add <path-to-packages/harnesssec>
```

Adapter hooks (Phase 0 verified): `tools/pre-execute` (block), `tools/result`, `session/event`, `agent/created`, `subagent/start`.
