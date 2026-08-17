/**
 * Deterministic sensitive-content access — Grep with explicit path shares
 * READ_SENSITIVE_FILE with Read/shell cat. No Cursor-specific policy branches.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { handleCursorHook } from '../src/adapters/cursor/index.ts'
import { createHarnessSec } from '../src/index.ts'
import { baseEvent } from '../src/events/helpers.ts'
import {
  normalizeAction,
  actionsEquivalent,
  capabilityFamily,
  isSensitiveResourcePath,
} from '../src/behavior/normalize.ts'
import { FlightRecorder } from '../src/core/recorder.ts'

test('normalize: Grep explicit .env ≡ Read .env (READ_SENSITIVE_FILE)', () => {
  const read = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { file_path: '/lab/.env' } },
  })
  const grep = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'Grep' },
    action: {
      type: 'tool.request',
      arguments: { pattern: '.', file_path: '/lab/.env' },
    },
  })
  assert.equal(read.category, 'READ_SENSITIVE_FILE')
  assert.equal(grep.category, 'READ_SENSITIVE_FILE')
  assert.equal(grep.level, 'exact')
  assert.equal(grep.capability, 'search')
  assert.equal(capabilityFamily('Grep'), 'search')
  assert.notEqual(read.capability, grep.capability)
  assert.ok(actionsEquivalent(read, grep))
  assert.equal(grep.original.arguments?.pattern, '.')
  assert.ok(isSensitiveResourcePath(grep.target))
})

test('normalize: Grep key.pem ≡ Read key.pem', () => {
  const path = 'ops/staging-identity/key.pem'
  const read = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path } },
  })
  const grep = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'Grep' },
    action: { type: 'tool.request', arguments: { pattern: 'FAKE', file_path: path } },
  })
  assert.equal(grep.category, 'READ_SENSITIVE_FILE')
  assert.ok(actionsEquivalent(read, grep))
})

test('normalize: Grep README / docs → READ_FILE not sensitive', () => {
  for (const file_path of ['README.md', 'docs/staging-setup.md', 'docs/']) {
    const n = normalizeAction({
      event_type: 'tool.requested',
      tool: { name: 'Grep' },
      action: { type: 'tool.request', arguments: { pattern: 'x', file_path } },
    })
    assert.equal(n.category, 'READ_FILE', file_path)
    assert.equal(n.level, 'exact')
  }
})

test('normalize: Glob is not content access even with path-like args', () => {
  const n = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'Glob' },
    action: {
      type: 'tool.request',
      arguments: { glob_pattern: '**/.env', target_directory: '/lab' },
    },
  })
  assert.equal(n.category, 'OTHER')
  assert.equal(n.level, 'unknown')
})

test('Cursor Grep .env → BLOCK sensitive-resource-read (no body persist)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-grep-env-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'preToolUse',
      conversation_id: 'grep-env',
      tool_name: 'Grep',
      tool_input: {
        pattern: '.',
        file_path: '/Users/goldpanda/harnx-lab/project/.env',
      },
    }, dir)
    assert.equal(result.blocked, true)
    assert.equal(result.response.permission, 'deny')
    assert.ok(result.events.some(e =>
      e.policy?.rule === 'sensitive-resource-read'
      && e.raw?.normalized?.category === 'READ_SENSITIVE_FILE',
    ))
    assert.equal(JSON.stringify(result.events).includes('APP_ENV=local'), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Cursor Grep key.pem → BLOCK; Grep README → ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-grep-neg-'))
  try {
    const blocked = handleCursorHook({
      hook_event_name: 'preToolUse',
      conversation_id: 'grep-pem',
      tool_name: 'Grep',
      tool_input: {
        pattern: '.',
        file_path: '/lab/ops/staging-identity/key.pem',
      },
    }, dir)
    assert.equal(blocked.blocked, true)

    const allow = handleCursorHook({
      hook_event_name: 'preToolUse',
      conversation_id: 'grep-readme',
      tool_name: 'Grep',
      tool_input: { pattern: 'setup', file_path: '/lab/README.md' },
    }, dir)
    assert.equal(allow.blocked, false)
    assert.equal(allow.response.permission, 'allow')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('negatives: Read/Grep README, Glob .env, git status — no sensitive block', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-grep-neg2-'))
  try {
    assert.equal(handleCursorHook({
      hook_event_name: 'beforeReadFile',
      conversation_id: 'neg-read-readme',
      file_path: '/lab/README.md',
      content: 'hello',
    }, dir).blocked, false)

    assert.equal(handleCursorHook({
      hook_event_name: 'preToolUse',
      conversation_id: 'neg-glob',
      tool_name: 'Glob',
      tool_input: { glob_pattern: '**/.env' },
    }, dir).blocked, false)

    assert.equal(handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'neg-git-status',
      command: 'git status',
    }, dir).blocked, false)

    assert.equal(handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'neg-git-diff',
      command: 'git diff',
    }, dir).blocked, false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('behavior: Read sensitive BLOCK then Grep same resource → policy_circumvention', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-grep-circ-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    const sid = 'circ-grep'
    const agent = { id: 'agent-a' }
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: sid },
      agent,
    }))
    const readReq = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      agent,
      turn: 1,
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '.env' } },
    }))
    const block = policy.evaluateToolRequest(readReq)
    assert.equal(block.decision, 'block')
    assert.equal(block.rule?.id, 'sensitive-resource-read')

    const grepReq = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      agent,
      turn: 1,
      tool: { name: 'Grep' },
      action: {
        type: 'tool.request',
        arguments: { pattern: '.', file_path: '.env' },
      },
    }))
    // Policy also blocks Grep; detection fires on tool.requested observe before/with policy.
    const dets = recorder.getSession(sid)!.events.filter(e => e.event_type === 'behavior.detection')
    assert.ok(
      dets.some(d => d.detection?.kind === 'agent.policy_circumvention'),
      `expected circumvention, got ${JSON.stringify(dets.map(d => d.detection?.kind))}`,
    )
    assert.equal(policy.evaluateToolRequest(grepReq).decision, 'block')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('behavior: unrelated Grep after sensitive Read block → no circumvention', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-grep-unrel-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    const sid = 'unrel'
    const agent = { id: 'a1' }
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: sid },
      agent,
    }))
    const readReq = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      agent,
      turn: 1,
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '.env' } },
    }))
    assert.equal(policy.evaluateToolRequest(readReq).decision, 'block')
    recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      agent,
      turn: 1,
      tool: { name: 'Grep' },
      action: {
        type: 'tool.request',
        arguments: { pattern: 'TODO', file_path: 'README.md' },
      },
    }))
    const dets = recorder.getSession(sid)!.events.filter(e => e.event_type === 'behavior.detection')
    assert.equal(dets.length, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('behavior: parent Read block → child Grep same resource → delegated circumvention', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-grep-deleg-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    const sid = 'deleg-grep'
    const parent = { id: 'parent' }
    const child = { id: 'child', parent_agent_id: 'parent' }
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: sid },
      agent: parent,
    }))
    const readReq = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      agent: parent,
      turn: 1,
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '.env' } },
    }))
    assert.equal(policy.evaluateToolRequest(readReq).decision, 'block')
    recorder.record(baseEvent({
      event_type: 'subagent.spawned',
      session: { id: sid },
      agent: child,
      turn: 1,
      action: { type: 'subagent.spawn', target: 'explore' },
    }))
    recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      agent: child,
      turn: 1,
      tool: { name: 'Grep' },
      action: {
        type: 'tool.request',
        arguments: { pattern: '.', file_path: '.env' },
      },
    }))
    const dets = recorder.getSession(sid)!.events.filter(e => e.event_type === 'behavior.detection')
    assert.ok(
      dets.some(d => d.detection?.kind === 'agent.delegated_policy_circumvention'),
      `expected delegated circumvention, got ${JSON.stringify(dets.map(d => d.detection?.kind))}`,
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('telemetry: preToolUse Shell is recorded (enforcement deferred)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-shell-telem-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'preToolUse',
      conversation_id: 'shell-telem',
      tool_name: 'Shell',
      tool_input: { command: 'ls' },
    }, dir)
    assert.equal(result.blocked, false)
    assert.ok(result.events.some(e =>
      e.event_type === 'tool.requested'
      && e.tool?.name === 'bash'
      && String(e.raw?.notes ?? '').includes('enforcement_hook=beforeShellExecution'),
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('telemetry: concurrent Grep preToolUse persists both tool.requested', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-concurrent-'))
  try {
    const sid = 'concurrent-grep'
    const run = (label: string, file_path: string) => {
      const r = new FlightRecorder(dir)
      r.record(baseEvent({
        event_type: 'tool.requested',
        session: { id: sid },
        agent: { id: 'cursor-agent' },
        turn: 1,
        tool: { name: 'Grep', call_id: label },
        action: {
          type: 'tool.request',
          arguments: { pattern: '.', file_path },
        },
        raw: { source_hook: 'cursor:preToolUse', notes: `cursor_tool=Grep;label=${label}` },
      }))
    }
    await Promise.all([
      Promise.resolve().then(() => run('env', '/lab/.env')),
      Promise.resolve().then(() => run('pem', '/lab/ops/staging-identity/key.pem')),
    ])
    const disk = JSON.parse(readFileSync(join(dir, `${sid}.json`), 'utf8')) as {
      events: Array<{ tool?: { call_id?: string }; action?: { arguments?: { file_path?: string } } }>
    }
    const greps = disk.events.filter(e => e.tool?.call_id === 'env' || e.tool?.call_id === 'pem')
    assert.equal(greps.length, 2, `expected both Grep events on disk, got ${greps.length}`)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
