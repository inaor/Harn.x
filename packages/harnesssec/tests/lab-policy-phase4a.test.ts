/**
 * Phase 4A lab policy — resource-centric matching via ActionNormalizer.
 * Shell cat and Cursor Read of the controlled path must BLOCK equivalently.
 * DeepSeek/OpenHands and default Cursor remain on defaultRules only.
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
import { normalizeAction, actionsEquivalent } from '../src/behavior/normalize.ts'
import {
  labControlledResourceRead,
  phase4aLabRules,
  PHASE4A_CONTROLLED_RESOURCE_PATH,
  isPhase4aControlledResourceRead,
} from '../src/policy/experimental/phase4a-lab-rules.ts'
import {
  CURSOR_LAB_POLICY_PHASE4A,
  resolveCursorHookRules,
} from '../src/cli/cursor-lab-policy.ts'
import { PolicyEngine } from '../src/policy/engine.ts'
import { FlightRecorder } from '../src/core/recorder.ts'

const CONTROLLED = PHASE4A_CONTROLLED_RESOURCE_PATH
const CONTROLLED_ABS = `/Users/goldpanda/harnx-lab/project/${CONTROLLED}`
const LAB_RULES = [...defaultRules, ...phase4aLabRules]

function shellReadEvent(command: string) {
  return {
    event_type: 'tool.requested' as const,
    tool: { name: 'bash', sensitivity: 'low' as const },
    action: {
      type: 'tool.request' as const,
      target: 'bash',
      arguments: { command },
    },
  }
}

function readToolEvent(path: string) {
  return {
    event_type: 'tool.requested' as const,
    tool: { name: 'read', sensitivity: 'low' as const },
    action: {
      type: 'tool.request' as const,
      target: 'read',
      arguments: { path },
    },
  }
}

function readToolEventFilePath(filePath: string) {
  return {
    event_type: 'tool.requested' as const,
    tool: { name: 'read', sensitivity: 'low' as const },
    action: {
      type: 'tool.request' as const,
      target: 'read',
      arguments: { file_path: filePath },
    },
  }
}

test('experimental lab rules are not in defaultRules', () => {
  assert.equal(defaultRules.some(r => r.id === 'lab-controlled-resource-read'), false)
  assert.equal(phase4aLabRules.some(r => r.id === labControlledResourceRead.id), true)
})

test('normalizeAction: shell cat and Read share READ_FILE + controlled resource semantics', () => {
  const shell = normalizeAction(shellReadEvent(`cat ${CONTROLLED}`))
  const readRel = normalizeAction(readToolEvent(CONTROLLED))
  const readAbs = normalizeAction(readToolEvent(CONTROLLED_ABS))
  const readFilePath = normalizeAction(readToolEventFilePath(CONTROLLED_ABS))

  assert.equal(shell.category, 'READ_FILE')
  assert.equal(shell.level, 'strong')
  assert.equal(shell.target, CONTROLLED)

  assert.equal(readRel.category, 'READ_FILE')
  assert.equal(readRel.level, 'exact')
  assert.equal(readRel.target, CONTROLLED)

  assert.ok(isPhase4aControlledResourceRead(shell))
  assert.ok(isPhase4aControlledResourceRead(readRel))
  assert.ok(isPhase4aControlledResourceRead(readAbs))
  assert.ok(isPhase4aControlledResourceRead(readFilePath))

  // Relative shell/Read targets are equivalent; absolute shares category+resource match
  assert.equal(actionsEquivalent(shell, readRel), true)
  assert.equal(shell.original.tool_name, 'bash')
  assert.equal(readRel.original.tool_name, 'read')
})

test('resolveCursorHookRules injects lab rules only for phase4a', () => {
  assert.equal(resolveCursorHookRules({}).some(r => r.id === 'lab-controlled-resource-read'), false)
  assert.equal(
    resolveCursorHookRules({ HARNX_LAB_POLICY: CURSOR_LAB_POLICY_PHASE4A })
      .some(r => r.id === 'lab-controlled-resource-read'),
    true,
  )
})

test('Phase4A lab: shell cat controlled path → BLOCK', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-lab-shell-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'lab-shell-block',
      command: `cat ${CONTROLLED}`,
    }, dir, LAB_RULES)
    assert.equal(result.blocked, true)
    assert.equal(result.response.permission, 'deny')
    assert.ok(result.events.some(e =>
      e.event_type === 'policy.decision'
      && e.policy?.rule === 'lab-controlled-resource-read'
      && e.policy?.decision === 'block'
      && e.raw?.normalized?.category === 'READ_FILE'
      && e.raw?.normalized?.target === CONTROLLED,
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Phase4A lab: Cursor Read controlled path → BLOCK', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-lab-read-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeReadFile',
      conversation_id: 'lab-read-block',
      file_path: CONTROLLED_ABS,
      content: 'HARNX_CONTROL_MARKER_74291\n',
    }, dir, LAB_RULES)
    assert.equal(result.blocked, true)
    assert.equal(result.response.permission, 'deny')
    assert.ok(result.events.some(e =>
      e.event_type === 'policy.decision'
      && e.policy?.rule === 'lab-controlled-resource-read',
    ))
    // Full content must not be persisted
    const blob = JSON.stringify(result.events)
    assert.equal(blob.includes('HARNX_CONTROL_MARKER_74291'), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Phase4A lab: Cursor preToolUse Read controlled path → BLOCK', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-lab-pre-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'preToolUse',
      conversation_id: 'lab-pre-block',
      tool_name: 'Read',
      tool_input: { file_path: CONTROLLED_ABS },
      tool_use_id: 'toolu_test',
    }, dir, LAB_RULES)
    assert.equal(result.blocked, true)
    assert.equal(result.response.permission, 'deny')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('negative: shell cat docs/readme.txt → ALLOW under lab rules', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-lab-neg-shell-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'lab-neg-shell',
      command: 'cat docs/readme.txt',
    }, dir, LAB_RULES)
    assert.equal(result.blocked, false)
    assert.equal(result.response.permission, 'allow')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('negative: Cursor Read docs/readme.txt → ALLOW under lab rules', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-lab-neg-read-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeReadFile',
      conversation_id: 'lab-neg-read',
      file_path: '/Users/goldpanda/harnx-lab/project/docs/readme.txt',
      content: 'hello',
    }, dir, LAB_RULES)
    assert.equal(result.blocked, false)
    assert.equal(result.response.permission, 'allow')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Normal Cursor (defaultRules): controlled Read/Shell → ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-default-'))
  try {
    const shell = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'def-shell',
      command: `cat ${CONTROLLED}`,
    }, dir)
    assert.equal(shell.blocked, false)
    const read = handleCursorHook({
      hook_event_name: 'beforeReadFile',
      conversation_id: 'def-read',
      file_path: CONTROLLED_ABS,
      content: 'x',
    }, dir)
    assert.equal(read.blocked, false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('DeepSeek with HARNX_LAB_POLICY set → controlled path still ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-dsh-'))
  const prev = process.env.HARNX_LAB_POLICY
  process.env.HARNX_LAB_POLICY = 'phase4a'
  try {
    const { recorder, policy } = createRuntime(dir)
    const sid = 'dsh'
    recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: 'deepseek-dsh' },
      session: { id: sid },
      agent: { id: 'a' },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: 'deepseek-dsh' },
      session: { id: sid },
      turn: 1,
      agent: { id: 'a' },
      tool: { name: 'bash' },
      action: { type: 'tool.request', target: 'bash', arguments: { command: `cat ${CONTROLLED}` } },
    }))
    assert.equal(policy.evaluateToolRequest(req).decision, 'allow')
  } finally {
    if (prev === undefined) delete process.env.HARNX_LAB_POLICY
    else process.env.HARNX_LAB_POLICY = prev
    rmSync(dir, { recursive: true, force: true })
  }
})

test('OpenHands with HARNX_LAB_POLICY set → controlled path still ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-oh-'))
  const prev = process.env.HARNX_LAB_POLICY
  process.env.HARNX_LAB_POLICY = 'phase4a'
  try {
    const { recorder, policy } = createOpenHandsRuntime(dir)
    const sid = 'oh'
    recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: 'openhands' },
      session: { id: sid },
      agent: { id: 'a' },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: 'openhands' },
      session: { id: sid },
      turn: 1,
      agent: { id: 'a' },
      tool: { name: 'read' },
      action: { type: 'tool.request', target: 'read', arguments: { path: CONTROLLED } },
    }))
    assert.equal(policy.evaluateToolRequest(req).decision, 'allow')
  } finally {
    if (prev === undefined) delete process.env.HARNX_LAB_POLICY
    else process.env.HARNX_LAB_POLICY = prev
    rmSync(dir, { recursive: true, force: true })
  }
})

test('PolicyEngine records normalized snapshot on decision', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-eng-'))
  try {
    const recorder = new FlightRecorder(dir)
    const policy = new PolicyEngine(recorder, LAB_RULES)
    const sid = 'eng'
    recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: 'cursor' },
      session: { id: sid },
      agent: { id: 'a' },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: 'cursor' },
      session: { id: sid },
      turn: 1,
      agent: { id: 'a' },
      tool: { name: 'read' },
      action: { type: 'tool.request', target: 'read', arguments: { path: CONTROLLED } },
    }))
    const v = policy.evaluateToolRequest(req)
    assert.equal(v.decision, 'block')
    assert.equal(v.event.raw?.normalized?.category, 'READ_FILE')
    assert.equal(v.event.raw?.normalized?.target, CONTROLLED)
    assert.equal(v.event.raw?.normalized?.tool_name, 'read')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
