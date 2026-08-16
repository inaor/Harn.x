import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { BehavioralEngine, createHarnessSec } from '../src/index.js'
import { baseEvent } from '../src/events/helpers.js'
import {
  BLOCKED_ACTION_DELEGATION_TTL_MS,
  DELEGATION_TO_CHILD_ACTION_MS,
} from '../src/behavior/index.js'
import { CapabilityTracker } from '../src/graph/capabilities.js'

function dir(): string {
  return mkdtempSync(join(tmpdir(), 'harnx-p3h-'))
}

function ts(base: number, offsetSec: number): string {
  return new Date(base + offsetSec * 1000).toISOString()
}

const T0 = Date.UTC(2026, 7, 16, 12, 0, 0)

test('hardening: lineage does not leak across sessions with reused agent ids', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }

  // Session A: child → parent-A
  engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session: { id: 'session-a' },
    agent: { id: 'child', parent_agent_id: 'parent-A' },
    timestamp: ts(T0, 0),
    links: { parent_agent: 'parent-A', delegated_by: 'parent-A' },
  }))
  assert.equal(engine.parentOf('session-a', 'child'), 'parent-A')
  assert.equal(engine.parentOf('session-b', 'child'), undefined)

  // Session B: same child id, no parent
  engine.observe(baseEvent({
    event_type: 'agent.started',
    harness,
    session: { id: 'session-b' },
    agent: { id: 'child' },
    timestamp: ts(T0, 1),
  }))
  assert.equal(engine.parentOf('session-b', 'child'), undefined)
  assert.equal(engine.parentOf('session-a', 'child'), 'parent-A')
})

test('hardening: capability snapshots do not leak across sessions', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'openhands' }

  engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session: { id: 'sa' },
    agent: { id: 'agent-1' },
    capability: { available: ['bash', 'shell.execute'] },
    timestamp: ts(T0, 0),
  }))
  assert.deepEqual(engine.snapshotFor('sa', 'agent-1'), ['bash', 'shell.execute'])
  assert.deepEqual(engine.snapshotFor('sb', 'agent-1'), [])

  engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session: { id: 'sb' },
    agent: { id: 'agent-1' },
    capability: { available: ['read'] },
    timestamp: ts(T0, 1),
  }))
  assert.deepEqual(engine.snapshotFor('sa', 'agent-1'), ['bash', 'shell.execute'])
  assert.deepEqual(engine.snapshotFor('sb', 'agent-1'), ['read'])
})

test('hardening: capability.snapshot replaces available set (revocation)', () => {
  const caps = new CapabilityTracker()
  const session = { id: 's1' }
  const agent = { id: 'a1' }

  caps.observe(baseEvent({
    event_type: 'capability.snapshot',
    session,
    agent,
    capability: { available: ['read', 'shell'] },
  }))
  assert.deepEqual(caps.availableFor('s1', 'a1'), ['read', 'shell'])

  caps.observe(baseEvent({
    event_type: 'capability.snapshot',
    session,
    agent,
    capability: { available: ['read'] },
  }))
  assert.deepEqual(caps.availableFor('s1', 'a1'), ['read'])

  // USED history still accumulates
  caps.observe(baseEvent({
    event_type: 'tool.requested',
    session,
    agent,
    tool: { name: 'shell' },
    action: { type: 'tool.request', arguments: {} },
  }))
  assert.deepEqual(caps.usedBy('s1', 'a1'), ['shell'])
  assert.deepEqual(caps.availableFor('s1', 'a1'), ['read'])
})

test('hardening: privilege expansion — spawn with snapshot (sequence A)', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }
  const session = { id: 'priv-a' }

  engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'parent' },
    capability: { available: ['read'] },
    timestamp: ts(T0, 0),
  }))

  const dets = engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    capability: { available: ['read', 'shell.execute'] },
    timestamp: ts(T0, 1),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  }))

  assert.ok(dets.some(d => d.detection?.kind === 'agent.delegation_privilege_expansion'))
})

test('hardening: privilege expansion — child snapshot after spawn (sequence B)', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'openhands' }
  const session = { id: 'priv-b' }

  engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'parent' },
    capability: { available: ['read'] },
    timestamp: ts(T0, 0),
  }))

  assert.deepEqual(engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 1),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  })), [])

  const dets = engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    capability: { available: ['read', 'shell.execute'] },
    timestamp: ts(T0, 2),
  }))

  assert.ok(dets.some(d => d.detection?.kind === 'agent.delegation_privilege_expansion'))
})

test('hardening: delegated circumvention — block→spawn+120s→child+5s DETECT', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }
  const session = { id: 'del-ok' }

  const bash = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: { name: 'bash', sensitivity: 'high' },
    action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
  })
  engine.observe(bash)
  engine.observe(baseEvent({
    event_type: 'policy.decision',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: bash.tool,
    action: bash.action,
    policy: { decision: 'block', rule: 'credential-path-in-shell-args' },
    links: { policy_decision_for: bash.id },
  }))

  engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 120),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  }))

  const dets = engine.observe(baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 125),
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  }))

  assert.ok(
    dets.some(d => d.detection?.kind === 'agent.delegated_policy_circumvention'),
    'expected DETECT within spawn→action window after late spawn',
  )
  assert.ok(BLOCKED_ACTION_DELEGATION_TTL_MS >= 120_000)
  assert.ok(DELEGATION_TO_CHILD_ACTION_MS === 30_000)
})

test('hardening: delegated circumvention — spawn+120s child+200s NO DETECT', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }
  const session = { id: 'del-late' }

  const bash = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: { name: 'bash', sensitivity: 'high' },
    action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
  })
  engine.observe(bash)
  engine.observe(baseEvent({
    event_type: 'policy.decision',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: bash.tool,
    action: bash.action,
    policy: { decision: 'block', rule: 'x' },
    links: { policy_decision_for: bash.id },
  }))
  engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 120),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  }))

  const dets = engine.observe(baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 200), // 80s after spawn > 30s window
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  }))

  assert.equal(
    dets.filter(d => d.detection?.kind === 'agent.delegated_policy_circumvention').length,
    0,
  )
})

test('hardening: delegated circumvention — unrelated child action NO DETECT', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }
  const session = { id: 'del-unrel' }

  const bash = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: { name: 'bash', sensitivity: 'high' },
    action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
  })
  engine.observe(bash)
  engine.observe(baseEvent({
    event_type: 'policy.decision',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: bash.tool,
    action: bash.action,
    policy: { decision: 'block', rule: 'x' },
    links: { policy_decision_for: bash.id },
  }))
  engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 10),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  }))

  const dets = engine.observe(baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 12),
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: 'git status' } },
  }))

  assert.equal(
    dets.filter(d => d.detection?.kind === 'agent.delegated_policy_circumvention').length,
    0,
  )
})

test('hardening: hydrate two sessions with reused agent ids stay isolated', () => {
  const store = dir()
  try {
    const { recorder, policy } = createHarnessSec(store)
    const harness = { name: 'deepseek-dsh' }

    // Session A with lineage + block + circumvention
    const sa = 'hydrate-a'
    const bashA = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sa },
      agent: { id: 'shared-agent' },
      timestamp: ts(T0, 0),
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
    })
    recorder.record(bashA)
    policy.evaluateToolRequest(bashA)
    recorder.record(baseEvent({
      event_type: 'capability.snapshot',
      harness,
      session: { id: sa },
      agent: { id: 'shared-agent' },
      capability: { available: ['bash', 'cloud.admin'] },
      timestamp: ts(T0, 1),
    }))
    recorder.record(baseEvent({
      event_type: 'subagent.spawned',
      harness,
      session: { id: sa },
      agent: { id: 'child', parent_agent_id: 'shared-agent' },
      timestamp: ts(T0, 2),
      links: { parent_agent: 'shared-agent', delegated_by: 'shared-agent' },
      capability: { available: ['bash', 'read'] },
    }))

    // Session B: same agent ids, no parent, different snapshot
    const sb = 'hydrate-b'
    recorder.record(baseEvent({
      event_type: 'agent.started',
      harness,
      session: { id: sb },
      agent: { id: 'shared-agent' },
      timestamp: ts(T0, 10),
    }))
    recorder.record(baseEvent({
      event_type: 'capability.snapshot',
      harness,
      session: { id: sb },
      agent: { id: 'shared-agent' },
      capability: { available: ['read'] },
      timestamp: ts(T0, 11),
    }))
    recorder.record(baseEvent({
      event_type: 'agent.started',
      harness,
      session: { id: sb },
      agent: { id: 'child' },
      timestamp: ts(T0, 12),
    }))

    // Reload from disk
    const { recorder: reloaded } = createHarnessSec(store)
    const eng = reloaded.behavior

    assert.equal(eng.parentOf(sa, 'child'), 'shared-agent')
    assert.equal(eng.hasObservedSpawn(sa, 'child'), true)
    assert.equal(eng.parentOf(sb, 'child'), undefined)
    assert.equal(eng.hasObservedSpawn(sb, 'child'), false)
    assert.deepEqual(eng.snapshotFor(sa, 'shared-agent'), ['bash', 'cloud.admin'])
    assert.deepEqual(eng.snapshotFor(sb, 'shared-agent'), ['read'])
    assert.ok(eng.memory.forAgent(sa, 'shared-agent').length >= 1)
    assert.equal(eng.memory.forAgent(sb, 'shared-agent').length, 0)

    // Caps tracker isolation
    assert.deepEqual(reloaded.capabilities.availableFor(sa, 'shared-agent'), ['bash', 'cloud.admin'])
    assert.deepEqual(reloaded.capabilities.availableFor(sb, 'shared-agent'), ['read'])
  } finally {
    rmSync(store, { recursive: true, force: true })
  }
})

test('consistency: parent_agent_id alone does not fabricate spawn — no delegated circumvention', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }
  const session = { id: 'no-spawn' }

  const bash = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: { name: 'bash', sensitivity: 'high' },
    action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
  })
  engine.observe(bash)
  engine.observe(baseEvent({
    event_type: 'policy.decision',
    harness,
    session,
    agent: { id: 'parent' },
    timestamp: ts(T0, 0),
    tool: bash.tool,
    action: bash.action,
    policy: { decision: 'block', rule: 'x' },
    links: { policy_decision_for: bash.id },
  }))

  // Child tool with parent_agent_id but NO subagent.spawned
  const noSpawn = engine.observe(baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 5),
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  }))
  assert.equal(engine.parentOf(session.id, 'child'), 'parent')
  assert.equal(engine.hasObservedSpawn(session.id, 'child'), false)
  assert.equal(
    noSpawn.filter(d => d.detection?.kind === 'agent.delegated_policy_circumvention').length,
    0,
  )
  const node = engine.lineageFor(session.id, 'child')
  assert.ok(node)
  assert.equal(node.spawn_timestamp, undefined)
  assert.equal(node.spawn_event_id, undefined)

  // Real spawn then equivalent child action → DETECT
  engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 10),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  }))
  assert.equal(engine.hasObservedSpawn(session.id, 'child'), true)

  const dets = engine.observe(baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 12),
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  }))
  assert.ok(dets.some(d => d.detection?.kind === 'agent.delegated_policy_circumvention'))
})

test('consistency: privilege expansion — spawn then child snap then parent snap', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }
  const session = { id: 'priv-order-c' }

  assert.deepEqual(engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 0),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  })), [])

  assert.deepEqual(engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'child' },
    capability: { available: ['read', 'shell'] },
    timestamp: ts(T0, 1),
  })), [])

  const dets = engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'parent' },
    capability: { available: ['read'] },
    timestamp: ts(T0, 2),
  }))
  assert.ok(dets.some(d => d.detection?.kind === 'agent.delegation_privilege_expansion'))
})

test('consistency: privilege expansion — child snap then parent snap then spawn (no duplicate)', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'openhands' }
  const session = { id: 'priv-order-d' }

  assert.deepEqual(engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'child' },
    capability: { available: ['read', 'shell'] },
    timestamp: ts(T0, 0),
  })), [])

  assert.deepEqual(engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'parent' },
    capability: { available: ['read'] },
    timestamp: ts(T0, 1),
  })), [])

  const dets = engine.observe(baseEvent({
    event_type: 'subagent.spawned',
    harness,
    session,
    agent: { id: 'child', parent_agent_id: 'parent' },
    timestamp: ts(T0, 2),
    links: { parent_agent: 'parent', delegated_by: 'parent' },
  }))
  assert.equal(
    dets.filter(d => d.detection?.kind === 'agent.delegation_privilege_expansion').length,
    1,
  )

  // Later snapshots must not duplicate
  const again = engine.observe(baseEvent({
    event_type: 'capability.snapshot',
    harness,
    session,
    agent: { id: 'child' },
    capability: { available: ['read', 'shell', 'extra'] },
    timestamp: ts(T0, 3),
  }))
  assert.equal(
    again.filter(d => d.detection?.kind === 'agent.delegation_privilege_expansion').length,
    0,
  )
})

test('consistency: hydrate preserves parent-only vs observed spawn for delegated circumvention', () => {
  const store = dir()
  try {
    const { recorder, policy } = createHarnessSec(store)
    const harness = { name: 'deepseek-dsh' }
    const session = { id: 'hydrate-parent-only' }

    const bash = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: session },
      agent: { id: 'parent' },
      timestamp: ts(T0, 0),
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
    })
    recorder.record(bash)
    policy.evaluateToolRequest(bash)

    // Persist parent relationship without spawn
    recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: session },
      agent: { id: 'child', parent_agent_id: 'parent' },
      timestamp: ts(T0, 5),
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '/tmp/readme.md' } },
    }))

    const { recorder: reloaded } = createHarnessSec(store)
    const eng = reloaded.behavior
    assert.equal(eng.parentOf(session, 'child'), 'parent')
    assert.equal(eng.hasObservedSpawn(session, 'child'), false)
    assert.equal(eng.lineageFor(session, 'child')?.spawn_timestamp, undefined)

    // After hydrate, equivalent sensitive action still must NOT detect without spawn
    const dets = eng.observe(baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: session },
      agent: { id: 'child', parent_agent_id: 'parent' },
      timestamp: ts(T0, 8),
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
    }))
    assert.equal(
      dets.filter(d => d.detection?.kind === 'agent.delegated_policy_circumvention').length,
      0,
    )
  } finally {
    rmSync(store, { recursive: true, force: true })
  }
})
