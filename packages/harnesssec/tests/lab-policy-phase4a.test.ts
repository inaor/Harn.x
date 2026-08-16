/**
 * Phase 4A lab policy injection — explicit, Cursor-hook-boundary only.
 * Proves DeepSeek/OpenHands ignore HARNX_LAB_POLICY; Cursor defaults stay
 * production unless lab rules are passed explicitly.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { handleCursorHook } from '../src/adapters/cursor/index.ts'
import { createRuntime } from '../src/adapters/deepseek/index.ts'
import { createOpenHandsRuntime } from '../src/adapters/openhands/index.ts'
import { baseEvent } from '../src/events/helpers.ts'
import { defaultRules } from '../src/policy/rules.ts'
import {
  labControlledResourceShellRead,
  phase4aLabRules,
  PHASE4A_CONTROLLED_RESOURCE_PATH,
} from '../src/policy/experimental/phase4a-lab-rules.ts'
import {
  CURSOR_LAB_POLICY_PHASE4A,
  resolveCursorHookRules,
} from '../src/cli/cursor-lab-policy.ts'
import { PolicyEngine } from '../src/policy/engine.ts'
import { FlightRecorder } from '../src/core/recorder.ts'

const CONTROLLED_CMD = `cat ${PHASE4A_CONTROLLED_RESOURCE_PATH}`

test('experimental lab rules are not in defaultRules', () => {
  assert.equal(defaultRules.some(r => r.id === 'lab-controlled-resource-shell-read'), false)
  assert.equal(phase4aLabRules.length >= 1, true)
})

test('resolveCursorHookRules: env only at CLI boundary; empty → defaultRules', () => {
  const rules = resolveCursorHookRules({})
  assert.equal(rules.length, defaultRules.length)
  assert.equal(rules.some(r => r.id === 'lab-controlled-resource-shell-read'), false)
})

test('resolveCursorHookRules: HARNX_LAB_POLICY=phase4a appends experimental rules', () => {
  const rules = resolveCursorHookRules({ HARNX_LAB_POLICY: CURSOR_LAB_POLICY_PHASE4A })
  assert.equal(rules.length, defaultRules.length + phase4aLabRules.length)
  assert.equal(rules.some(r => r.id === labControlledResourceShellRead.id), true)
})

test('Normal Cursor: controlled resource → default allow (no lab rules injected)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-default-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'c-default-ctrl',
      command: CONTROLLED_CMD,
      cwd: '/tmp/lab',
    }, dir)
    assert.equal(result.blocked, false)
    assert.equal(result.response.permission, 'allow')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Phase4A Cursor lab: controlled resource → BLOCK when lab rules injected explicitly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-lab-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'c-lab-ctrl',
      command: CONTROLLED_CMD,
      cwd: '/tmp/lab',
    }, dir, [...defaultRules, ...phase4aLabRules])
    assert.equal(result.blocked, true)
    assert.equal(result.response.permission, 'deny')
    assert.ok(result.events.some(e =>
      e.event_type === 'policy.decision'
      && e.policy?.decision === 'block'
      && e.policy?.rule === 'lab-controlled-resource-shell-read',
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Normal Cursor with HARNX_LAB_POLICY set but no explicit injection → still allow', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-env-leak-'))
  const prev = process.env.HARNX_LAB_POLICY
  process.env.HARNX_LAB_POLICY = 'phase4a'
  try {
    // Adapter default path ignores env — only CLI resolveCursorHookRules reads it.
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'c-env-ignored',
      command: CONTROLLED_CMD,
    }, dir)
    assert.equal(result.blocked, false)
    assert.equal(result.response.permission, 'allow')
  } finally {
    if (prev === undefined) delete process.env.HARNX_LAB_POLICY
    else process.env.HARNX_LAB_POLICY = prev
    rmSync(dir, { recursive: true, force: true })
  }
})

test('DeepSeek with HARNX_LAB_POLICY accidentally present → behavior unchanged (allow controlled)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-dsh-lab-env-'))
  const prev = process.env.HARNX_LAB_POLICY
  process.env.HARNX_LAB_POLICY = 'phase4a'
  try {
    const { recorder, policy } = createRuntime(dir)
    const sid = 'dsh-lab-env'
    recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: 'deepseek-dsh' },
      session: { id: sid },
      agent: { id: 'a1' },
    }))
    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: 'deepseek-dsh' },
      session: { id: sid },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'low' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: CONTROLLED_CMD },
      },
    }))
    const verdict = policy.evaluateToolRequest(requested)
    assert.equal(verdict.decision, 'allow')
    assert.equal(verdict.rule?.id, undefined)
  } finally {
    if (prev === undefined) delete process.env.HARNX_LAB_POLICY
    else process.env.HARNX_LAB_POLICY = prev
    rmSync(dir, { recursive: true, force: true })
  }
})

test('OpenHands with HARNX_LAB_POLICY accidentally present → behavior unchanged (allow controlled)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-oh-lab-env-'))
  const prev = process.env.HARNX_LAB_POLICY
  process.env.HARNX_LAB_POLICY = 'phase4a'
  try {
    const { recorder, policy } = createOpenHandsRuntime(dir)
    const sid = 'oh-lab-env'
    recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: 'openhands' },
      session: { id: sid },
      agent: { id: 'a1' },
    }))
    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: 'openhands' },
      session: { id: sid },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'low' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: CONTROLLED_CMD },
      },
    }))
    const verdict = policy.evaluateToolRequest(requested)
    assert.equal(verdict.decision, 'allow')
  } finally {
    if (prev === undefined) delete process.env.HARNX_LAB_POLICY
    else process.env.HARNX_LAB_POLICY = prev
    rmSync(dir, { recursive: true, force: true })
  }
})

test('lab rule still matches via PolicyEngine when composed explicitly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-lab-engine-'))
  try {
    const recorder = new FlightRecorder(dir)
    const policy = new PolicyEngine(recorder, [...defaultRules, ...phase4aLabRules])
    const sid = 'engine-lab'
    recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: 'cursor' },
      session: { id: sid },
      agent: { id: 'a1' },
    }))
    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: 'cursor' },
      session: { id: sid },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'low' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: CONTROLLED_CMD },
      },
    }))
    assert.equal(policy.evaluateToolRequest(requested).rule?.id, 'lab-controlled-resource-shell-read')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
