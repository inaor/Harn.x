# Harn.x Cursor Lab (Phase 4A)

Controlled environment for native Cursor Agent + Harn.x hooks.

**Always open:** `~/harnx-lab/project` in a **new** Cursor window.  
Never run the canonical proof inside the Harn.x source repository.

## Safety

- Canonical enforcement fixture is **inside** the workspace: `project/protected/build-info.txt`
  - Benign controlled resource (not a credential / SSH / API-key / token scenario)
  - Lab `env.sh` sets `HARNX_LAB_POLICY=phase4a`; **only** `cursor-hook` reads it and
    explicitly injects experimental **resource-centric** lab rules into PolicyEngine
    (normalized READ_FILE of `protected/build-info.txt` — Shell or Read)
  - Does not change DeepSeek / OpenHands / native Cursor defaultRules
- SSH / credential fixtures under `test-home/` and `fake-home/` remain for a **separate** scenario where `MODEL_SELF_REJECTED` is a valid outcome
- Never point tests at real `~/.ssh`, `~/.aws`, or production tokens
- Canonical enforcement: `beforeShellExecution` + `failClosed` + `permission:deny`

## Evidence (preserved)

```text
~/harnx-lab/evidence/sessions/<conversation_id>/
```

- Hooks **never** delete evidence.
- Setup archives prior sessions **only** when `HARNX_LAB_CLEAR_EVIDENCE=1` (before a run).
- Setup never clears evidence after a run.

## Setup

```bash
# From Harn.x repo root:
./scripts/setup-cursor-lab.sh

# Optional: archive old sessions before a clean run
HARNX_LAB_CLEAR_EVIDENCE=1 ./scripts/setup-cursor-lab.sh

cd packages/harnesssec && npm run build
```

Then: **File → New Window → Open** `~/harnx-lab/project`.

Operator protocol: `~/harnx-lab/CANONICAL_PROOF.md` (lab root — not required inside the Agent workspace).

## Inspect

```bash
ls ~/harnx-lab/evidence/sessions/
harnesssec sessions --store ~/harnx-lab/evidence/sessions/<conversation_id>
harnesssec why <session-id> --store ~/harnx-lab/evidence/sessions/<conversation_id>
```
