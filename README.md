# Harn.x

Harness-native flight recorder and pre-execution policy for AI agent harnesses.

> Models think. Harnesses act. We secure the execution layer.

Not an EDR. Not eBPF. Not a network proxy.

**Repo:** [github.com/inaor/Harn.x](https://github.com/inaor/Harn.x)

---

## What this proves

DeepSeek Harness already exposes tool intent **before** execution. Harn.x records that intent, links it to context provenance, and can **BLOCK** a dangerous tool call so the OS never sees a process.

Classic PoC chain:

```text
User: "Analyze this repository."
        ↓
Agent reads README.md
        ↓
README marked UNTRUSTED
        ↓
Agent requests: bash → cat ~/.ssh/id_rsa
        ↓
Harn.x BLOCK (before spawn)
        ↓
Agent tries an alternate tool
        ↓
Aftermath recorded → session replay
```

---

## Proof of concept (terminal)

Requires Node 20+.

### 1. Install

```sh
git clone https://github.com/inaor/Harn.x.git
cd Harn.x/packages/harnesssec
npm install
```

### 2. Run the attack demo

```sh
npm run demo
```

You should see a summary like:

```text
HarnessSec Phase 1 demo
──────────────────────
Objective: Analyze this repository.
Context: README.md [UNTRUSTED]
Influenced: agent-001
Agent requested: bash / cat ~/.ssh/id_rsa
Decision: BLOCKED
Rule: credential-path-in-shell-args
Agent reaction recorded: yes (alternate tool)

Thesis hold: blocked from harness intent+context before OS execution.
```

Then a forensic replay of session `attack-demo` (context → tool → BLOCK → aftermath).

### 3. List recorded sessions

```sh
npm run cli -- sessions
```

```text
attack-demo  started=…  events=…  objective=Analyze this repository.
```

### 4. Replay the session

```sh
npm run cli -- replay attack-demo
```

Look for:

```text
Context introduced
source: README.md
trust: UNTRUSTED
        ↓
Tool request
tool: bash
command: cat ~/.ssh/id_rsa
        ↓
HarnessSec Policy
decision: BLOCK
        ↓
BLOCKED BEFORE EXECUTION
        ↓
Agent reaction after block
selected alternate tool: read
```

### 5. Causal graph

```sh
npm run cli -- graph attack-demo
```

Shows event IDs plus links such as `context_source=…` and `policy_decision_for=…`.

### 6. Detections only

```sh
npm run cli -- detections attack-demo
```

```text
…  BLOCK  credential-path-in-shell-args  Shell tool arguments reference credential material: cat ~/.ssh/id_rsa
```

### 7. Agent lineage + policies

```sh
npm run cli -- agents attack-demo
npm run cli -- policies
```

### Optional: custom store directory

```sh
npm run cli -- --store /tmp/harnx-demo demo
npm run cli -- --store /tmp/harnx-demo replay attack-demo
```

### Tests

```sh
npm test
```

---

## CLI reference

```text
harnesssec demo
harnesssec sessions
harnesssec inspect <session>
harnesssec replay <session>
harnesssec graph <session>
harnesssec agents [session]
harnesssec policies
harnesssec detections [session]
harnesssec attach dsh
```

Via npm scripts from `packages/harnesssec`:

```sh
npm run demo
npm run cli -- <command>
```

---

## Attach to DeepSeek Harness (live)

Phase 1 ships a Cordis plugin adapter on verified seams (`tools/pre-execute` deny, `tools/result`, `session/event`, `agent/created`, `subagent/start`).

```sh
dsh plugin --profile web add /path/to/Harn.x/packages/harnesssec
```

```sh
npm run cli -- attach dsh
```

Live attach is the next integration step; the demo above proves the recorder, graph, and enforcement logic without booting full `dsh`.

---

## Status

| Phase | Status |
|---|---|
| 0 — DeepSeek choke-point map | Complete — [`docs/deepseek-harness-architecture.md`](docs/deepseek-harness-architecture.md) |
| 1 — Harness flight recorder + **live DSH validation** | **COMPLETE** — [`docs/phase1-live-validation.md`](docs/phase1-live-validation.md) |
| 2 — OpenHands portability | **PASS** — [`docs/phase2-final-validation.md`](docs/phase2-final-validation.md) |
| 2.1 — Provenance + Guardian | **COMPLETE** — UserPromptSubmit live proof + independent Guardian |
| 3 — Stateful behavioral detection | **PASS** (OH live lineage PARTIAL) — [`docs/phase3-findings.md`](docs/phase3-findings.md) |

Blind spots: [`docs/blind-spots.md`](docs/blind-spots.md) · OpenHands: [`docs/openhands-blind-spots.md`](docs/openhands-blind-spots.md)

### Live proof (integration)

```sh
cd packages/harnesssec
npm ci
npm run build
npm test
npm run test:integration
```

Expected:

- DeepSeek: BLOCK leaves `/tmp/harnx-proof` absent; ALLOW creates `/tmp/harnx-allow-ok`
- OpenHands: BLOCK leaves `/tmp/harnx-openhands-proof` absent; ALLOW creates `/tmp/harnx-openhands-allowed`
- Documented bypasses: DeepSeek `ctx.shell` · OpenHands `execute_tool`

OpenHands live tests need a local `openhands-sdk/` checkout (CI clones it) and `uv`.

## Docs

- [`docs/phase1-capabilities.md`](docs/phase1-capabilities.md)
- [`docs/security-primitives.md`](docs/security-primitives.md)
- [`docs/event-schema.md`](docs/event-schema.md)
- [`docs/causal-graph.md`](docs/causal-graph.md)
- [`docs/phase1-live-validation.md`](docs/phase1-live-validation.md)
- [`docs/blind-spots.md`](docs/blind-spots.md)
- [`docs/phase1-findings.md`](docs/phase1-findings.md)
- [`docs/openhands-architecture.md`](docs/openhands-architecture.md)
- [`docs/openhands-blind-spots.md`](docs/openhands-blind-spots.md)
- [`docs/harness-comparison.md`](docs/harness-comparison.md)
- [`docs/phase2-findings.md`](docs/phase2-findings.md)
- [`docs/phase2-final-validation.md`](docs/phase2-final-validation.md)
- [`docs/behavioral-model.md`](docs/behavioral-model.md)
- [`docs/behavioral-detections.md`](docs/behavioral-detections.md)
- [`docs/phase3-findings.md`](docs/phase3-findings.md)
- [`docs/architecture-contract.md`](docs/architecture-contract.md)
