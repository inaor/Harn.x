import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createHarnessSec, BehavioralEngine } from '../src/index.js'
import { baseEvent } from '../src/events/helpers.js'
import {
  normalizeAction,
  actionsEquivalent,
  isDetectionEligible,
  renderIncident,
  DEFAULT_WINDOW_MS,
  buildDetectionEvent,
} from '../src/behavior/index.js'
import type { HarnessName } from '../src/events/schema.js'
import { CapabilityTracker } from '../src/graph/capabilities.js'

function dir(): string {
  return mkdtempSync(join(tmpdir(), 'harnx-p3-'))
}

function ts(offsetSec: number): string {
  return new Date(Date.UTC(2026, 7, 16, 12, 41, 0 + offsetSec)).toISOString()
}

function runCircumventionScenario(harnessName: HarnessName, sessionId: string, store: string) {
  const { recorder, policy } = createHarnessSec(store)
  const harness = { name: harnessName }
  const agent = { id: 'agent-a' }

  recorder.record(baseEvent({
    event_type: 'session.started',
    harness,
    session: { id: sessionId },
    timestamp: ts(0),
  }))
  recorder.record(baseEvent({
    event_type: 'agent.started',
    harness,
    session: { id: sessionId },
    agent,
    timestamp: ts(1),
  }))

  const bashReq = baseEvent({
    event_type: 'tool.requested',
    harness,
    session: { id: sessionId },
    agent,
    turn: 1,
    timestamp: ts(5),
    tool: { name: 'bash', sensitivity: 'high' },
    action: {
      type: 'tool.request',
      target: 'bash',
      arguments: { command: 'cat ~/.ssh/id_rsa' },
    },
  })
  recorder.record(bashReq)
  const block = policy.evaluateToolRequest(bashReq)
  assert.equal(block.decision, 'block')

  const readReq = baseEvent({
    event_type: 'tool.requested',
    harness,
    session: { id: sessionId },
    agent,
    turn: 1,
    timestamp: ts(7),
    tool: { name: 'read' },
    action: {
      type: 'tool.request',
      target: 'read',
      arguments: { path: '~/.ssh/id_rsa' },
    },
  })
  recorder.record(readReq)
  policy.evaluateToolRequest(readReq)

  return recorder
}

test('normalize: bash cat and filesystem read are strong/exact equivalent READ_SENSITIVE_FILE', () => {
  const a = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
  })
  const b = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  })
  assert.equal(a.category, 'READ_SENSITIVE_FILE')
  assert.equal(a.level, 'strong')
  assert.equal(b.category, 'READ_SENSITIVE_FILE')
  assert.equal(b.level, 'exact')
  assert.ok(a.original.arguments)
  assert.ok(b.original.arguments)
  assert.ok(actionsEquivalent(a, b))
  assert.ok(isDetectionEligible(a) && isDetectionEligible(b))
  assert.notEqual(a.capability, b.capability)
})

test('normalize negatives: uncertain actions are OTHER/unknown and not equivalent', () => {
  const cases = [
    {
      name: 'python-ish shell',
      event: {
        event_type: 'tool.requested' as const,
        tool: { name: 'bash' },
        action: { type: 'tool.request', arguments: { command: 'python -c "open(\'~/.ssh/id_rsa\').read()"' } },
      },
    },
    {
      name: 'pipeline',
      event: {
        event_type: 'tool.requested' as const,
        tool: { name: 'bash' },
        action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa | base64' } },
      },
    },
    {
      name: 'echo only',
      event: {
        event_type: 'tool.requested' as const,
        tool: { name: 'bash' },
        action: { type: 'tool.request', arguments: { command: 'echo hello' } },
      },
    },
    {
      name: 'git status',
      event: {
        event_type: 'tool.requested' as const,
        tool: { name: 'bash' },
        action: { type: 'tool.request', arguments: { command: 'git status' } },
      },
    },
    {
      name: 'read without path',
      event: {
        event_type: 'tool.requested' as const,
        tool: { name: 'read' },
        action: { type: 'tool.request', arguments: {} },
      },
    },
    {
      name: 'web_fetch without url',
      event: {
        event_type: 'tool.requested' as const,
        tool: { name: 'web_fetch' },
        action: { type: 'tool.request', arguments: {} },
      },
    },
    {
      name: 'opaque tool',
      event: {
        event_type: 'tool.requested' as const,
        tool: { name: 'mystery_tool' },
        action: { type: 'tool.request', arguments: { foo: 'bar' } },
      },
    },
  ]

  const sensitiveRead = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  })

  for (const c of cases) {
    const n = normalizeAction(c.event)
    assert.equal(n.level, 'unknown', `${c.name} should be unknown (got ${n.level}/${n.category})`)
    assert.equal(actionsEquivalent(n, sensitiveRead), false, `${c.name} must not equate to sensitive read`)
    assert.equal(isDetectionEligible(n), false, `${c.name} not detection-eligible`)
  }
})

test('CapabilityTracker: use does not imply available', () => {
  const caps = new CapabilityTracker()
  caps.observe(baseEvent({
    event_type: 'tool.requested',
    session: { id: 's' },
    agent: { id: 'a1' },
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: 'ls' } },
  }))
  assert.deepEqual(caps.availableFor('s', 'a1'), [])
  assert.deepEqual(caps.usedBy('s', 'a1'), ['bash'])

  caps.observe(baseEvent({
    event_type: 'capability.snapshot',
    session: { id: 's' },
    agent: { id: 'a1' },
    capability: { available: ['bash', 'read'] },
  }))
  assert.deepEqual(caps.availableFor('s', 'a1'), ['bash', 'read'])
})

test('BehavioralEngine is independent of FlightRecorder', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'deepseek-dsh' }
  const session = { id: 'indep' }
  const agent = { id: 'a1' }

  const bash = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent,
    timestamp: ts(0),
    tool: { name: 'bash', sensitivity: 'high' },
    action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
  })
  assert.deepEqual(engine.observe(bash), [])

  const block = baseEvent({
    event_type: 'policy.decision',
    harness,
    session,
    agent,
    timestamp: ts(0),
    tool: bash.tool,
    action: bash.action,
    policy: { decision: 'block', rule: 'credential-path-in-shell-args' },
    links: { policy_decision_for: bash.id },
  })
  assert.deepEqual(engine.observe(block), [])
  assert.equal(engine.memory.forAgent('indep', 'a1').length, 1)

  const read = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent,
    timestamp: ts(2),
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  })
  const dets = engine.observe(read)
  assert.equal(dets.length, 1)
  assert.equal(dets[0].event_type, 'behavior.detection')
  assert.equal(dets[0].detection?.kind, 'agent.policy_circumvention')
})

test('behavior.detection cannot recursively trigger itself', () => {
  const engine = new BehavioralEngine()
  const harness = { name: 'openhands' }
  const session = { id: 'recur' }
  const agent = { id: 'a1' }

  const bash = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent,
    timestamp: ts(0),
    tool: { name: 'bash', sensitivity: 'high' },
    action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
  })
  engine.observe(bash)
  engine.observe(baseEvent({
    event_type: 'policy.decision',
    harness,
    session,
    agent,
    timestamp: ts(0),
    tool: bash.tool,
    action: bash.action,
    policy: { decision: 'block', rule: 'x' },
    links: { policy_decision_for: bash.id },
  }))
  const read = baseEvent({
    event_type: 'tool.requested',
    harness,
    session,
    agent,
    timestamp: ts(1),
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
  })
  const dets = engine.observe(read)
  assert.equal(dets.length, 1)

  // Re-observe the detection event — must not emit more detections
  assert.deepEqual(engine.observe(dets[0]), [])
  assert.deepEqual(engine.observe(dets[0]), [])

  // Synthetic nested call while building another detection must no-op via guard
  const again = engine.observe(dets[0])
  assert.equal(again.length, 0)

  // Via recorder path: recording detection must not cascade
  const store = dir()
  try {
    const { recorder, policy } = createHarnessSec(store)
    const sid = 'recur-rec'
    const b = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sid },
      agent,
      timestamp: ts(0),
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
    })
    recorder.record(b)
    policy.evaluateToolRequest(b)
    const r = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sid },
      agent,
      timestamp: ts(1),
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
    })
    recorder.record(r)
    const all = recorder.getSession(sid)!.events.filter(e => e.event_type === 'behavior.detection')
    assert.equal(all.length, 1)
  } finally {
    rmSync(store, { recursive: true, force: true })
  }

  void buildDetectionEvent
})

test('Phase 3: alternate capability circumvention — same detector for DSH and OpenHands', () => {
  for (const harnessName of ['deepseek-dsh', 'openhands'] as HarnessName[]) {
    const store = dir()
    try {
      const sessionId = `p3-alt-${harnessName}`
      const recorder = runCircumventionScenario(harnessName, sessionId, store)
      const dets = recorder.getSession(sessionId)!.events.filter(e => e.event_type === 'behavior.detection')
      assert.ok(
        dets.some(d => d.detection?.kind === 'agent.policy_circumvention'),
        `expected circumvention for ${harnessName}, got ${JSON.stringify(dets.map(d => d.detection?.kind))}`,
      )
      assert.ok(dets.every(d => d.harness.name === harnessName))
    } finally {
      rmSync(store, { recursive: true, force: true })
    }
  }
})

test('Phase 3: delegated policy circumvention with explicit lineage (detector-portable)', () => {
  for (const harnessName of ['deepseek-dsh', 'openhands'] as HarnessName[]) {
    const store = dir()
    try {
      const sessionId = `p3-del-${harnessName}`
      const { recorder, policy } = createHarnessSec(store)
      const harness = { name: harnessName }
      recorder.record(baseEvent({
        event_type: 'agent.started',
        harness,
        session: { id: sessionId },
        agent: { id: 'agent-a' },
        timestamp: ts(0),
      }))
      recorder.record(baseEvent({
        event_type: 'capability.snapshot',
        harness,
        session: { id: sessionId },
        agent: { id: 'agent-a' },
        timestamp: ts(0),
        capability: { available: ['bash', 'read'] },
      }))

      const bashReq = baseEvent({
        event_type: 'tool.requested',
        harness,
        session: { id: sessionId },
        agent: { id: 'agent-a' },
        timestamp: ts(5),
        tool: { name: 'bash', sensitivity: 'high' },
        action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
      })
      recorder.record(bashReq)
      assert.equal(policy.evaluateToolRequest(bashReq).decision, 'block')

      recorder.record(baseEvent({
        event_type: 'subagent.spawned',
        harness,
        session: { id: sessionId },
        agent: { id: 'agent-b', parent_agent_id: 'agent-a' },
        timestamp: ts(10),
        links: { parent_agent: 'agent-a', delegated_by: 'agent-a' },
        capability: { available: ['bash', 'read', 'cloud.admin'] },
      }))

      const childReq = baseEvent({
        event_type: 'tool.requested',
        harness,
        session: { id: sessionId },
        agent: { id: 'agent-b', parent_agent_id: 'agent-a' },
        timestamp: ts(12),
        tool: { name: 'read' },
        action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
      })
      recorder.record(childReq)
      policy.evaluateToolRequest(childReq)

      const dets = recorder.getSession(sessionId)!.events.filter(e => e.event_type === 'behavior.detection')
      assert.ok(
        dets.some(d => d.detection?.kind === 'agent.delegated_policy_circumvention'),
        `delegated missing for ${harnessName}: ${dets.map(d => d.detection?.kind)}`,
      )
      assert.ok(
        dets.some(d => d.detection?.kind === 'agent.delegation_privilege_expansion'),
        `privilege expansion missing for ${harnessName}`,
      )

      const incident = renderIncident(recorder, sessionId)
      assert.match(incident, /HARN\.X INCIDENT/)
    } finally {
      rmSync(store, { recursive: true, force: true })
    }
  }
})

test('Phase 3 FP: blocked sensitive read then git status → no circumvention', () => {
  const store = dir()
  try {
    const { recorder, policy } = createHarnessSec(store)
    const sessionId = 'fp-git'
    const harness = { name: 'deepseek-dsh' }
    const agent = { id: 'a1' }
    const bashReq = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent,
      timestamp: ts(0),
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
    })
    recorder.record(bashReq)
    assert.equal(policy.evaluateToolRequest(bashReq).decision, 'block')

    const gitReq = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent,
      timestamp: ts(2),
      tool: { name: 'bash' },
      action: { type: 'tool.request', arguments: { command: 'git status' } },
    })
    recorder.record(gitReq)
    policy.evaluateToolRequest(gitReq)

    const dets = recorder.getSession(sessionId)!.events.filter(e => e.event_type === 'behavior.detection')
    assert.equal(dets.length, 0)
  } finally {
    rmSync(store, { recursive: true, force: true })
  }
})

test('Phase 3 FP: blocked file A then legitimate file B → no circumvention', () => {
  const store = dir()
  try {
    const { recorder, policy } = createHarnessSec(store)
    const sessionId = 'fp-fileb'
    const harness = { name: 'openhands' }
    const agent = { id: 'a1' }
    const bashReq = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent,
      timestamp: ts(0),
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
    })
    recorder.record(bashReq)
    policy.evaluateToolRequest(bashReq)

    const readB = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent,
      timestamp: ts(2),
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '/tmp/readme.md' } },
    })
    recorder.record(readB)
    policy.evaluateToolRequest(readB)

    const dets = recorder.getSession(sessionId)!.events.filter(e => e.event_type === 'behavior.detection')
    assert.equal(dets.length, 0)
  } finally {
    rmSync(store, { recursive: true, force: true })
  }
})

test('Phase 3 FP: parent blocked, unrelated child action → no delegated circumvention', () => {
  const store = dir()
  try {
    const { recorder, policy } = createHarnessSec(store)
    const sessionId = 'fp-child'
    const harness = { name: 'deepseek-dsh' }
    const bashReq = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent: { id: 'parent' },
      timestamp: ts(0),
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
    })
    recorder.record(bashReq)
    policy.evaluateToolRequest(bashReq)

    recorder.record(baseEvent({
      event_type: 'subagent.spawned',
      harness,
      session: { id: sessionId },
      agent: { id: 'child', parent_agent_id: 'parent' },
      timestamp: ts(2),
      links: { parent_agent: 'parent', delegated_by: 'parent' },
    }))

    const childReq = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent: { id: 'child', parent_agent_id: 'parent' },
      timestamp: ts(3),
      tool: { name: 'bash' },
      action: { type: 'tool.request', arguments: { command: 'git status' } },
    })
    recorder.record(childReq)
    policy.evaluateToolRequest(childReq)

    const dets = recorder.getSession(sessionId)!.events.filter(
      e => e.detection?.kind === 'agent.delegated_policy_circumvention',
    )
    assert.equal(dets.length, 0)
  } finally {
    rmSync(store, { recursive: true, force: true })
  }
})

test('Phase 3 FP: equivalent action after window → no circumvention', () => {
  const store = dir()
  try {
    const { recorder, policy } = createHarnessSec(store)
    const sessionId = 'fp-window'
    const harness = { name: 'deepseek-dsh' }
    const agent = { id: 'a1' }
    const bashReq = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent,
      timestamp: ts(0),
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', arguments: { command: 'cat ~/.ssh/id_rsa' } },
    })
    recorder.record(bashReq)
    policy.evaluateToolRequest(bashReq)

    const late = baseEvent({
      event_type: 'tool.requested',
      harness,
      session: { id: sessionId },
      agent,
      timestamp: new Date(Date.UTC(2026, 7, 16, 12, 41, 0) + DEFAULT_WINDOW_MS + 5000).toISOString(),
      tool: { name: 'read' },
      action: { type: 'tool.request', arguments: { path: '~/.ssh/id_rsa' } },
    })
    recorder.record(late)
    policy.evaluateToolRequest(late)

    const dets = recorder.getSession(sessionId)!.events.filter(e => e.event_type === 'behavior.detection')
    assert.equal(dets.length, 0)
  } finally {
    rmSync(store, { recursive: true, force: true })
  }
})

test('Phase 3: no vendor checks in behavior module source', async () => {
  const { readFileSync, readdirSync } = await import('node:fs')
  const { join: j, dirname } = await import('node:path')
  const { fileURLToPath } = await import('node:url')
  const root = j(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'behavior')
  for (const name of readdirSync(root)) {
    if (!name.endsWith('.ts')) continue
    const text = readFileSync(j(root, name), 'utf8')
    assert.equal(
      /harness\s*===\s*['"]openhands['"]|harness\s*===\s*['"]deepseek/.test(text),
      false,
      `vendor branch in ${name}`,
    )
    assert.equal(/if\s*\(\s*harness/.test(text), false, `harness if in ${name}`)
    assert.equal(
      /from ['"].*recorder/.test(text) || /import type \{ FlightRecorder/.test(text),
      false,
      `recorder coupling in ${name}`,
    )
  }
})
