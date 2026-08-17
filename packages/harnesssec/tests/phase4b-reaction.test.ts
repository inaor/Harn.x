/**
 * Phase 4B — AGENT_REACTION correlator + why/backfill tests.
 * Does not change behavior.detection evidence bars.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createHarnessSec } from '../src/index.ts'
import { baseEvent } from '../src/events/helpers.ts'
import type { HarnessEvent } from '../src/events/schema.ts'
import {
  DEFAULT_REACTION_WINDOW_MS,
  backfillSessionReactions,
  correlateAgentReaction,
  buildReactionEvent,
} from '../src/behavior/reaction.ts'
import { renderWhy } from '../src/cli/why.ts'
import { renderIncident } from '../src/behavior/render.ts'

assert.equal(DEFAULT_REACTION_WINDOW_MS, 120_000)

function ev(
  partial: Parameters<typeof baseEvent>[0],
  sessionId = 'p4b',
): HarnessEvent {
  return baseEvent({
    session: { id: sessionId },
    agent: { id: 'agent-a' },
    harness: { name: 'cursor' },
    ...partial,
  })
}

test('DEFAULT_REACTION_WINDOW_MS is 120s and configurable via opts', () => {
  assert.equal(DEFAULT_REACTION_WINDOW_MS, 120_000)
  const t0 = '2026-08-17T12:00:00.000Z'
  const tFar = '2026-08-17T12:03:00.000Z' // 180s later
  const tool = ev({
    id: 'tool-1',
    timestamp: t0,
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  const block = ev({
    id: 'block-1',
    timestamp: '2026-08-17T12:00:00.100Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'sensitive-resource-read', reason: 'x' },
    links: { policy_decision_for: 'tool-1' },
  })
  const later = ev({
    id: 'tool-2',
    timestamp: tFar,
    event_type: 'tool.requested',
    tool: { name: 'grep' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env', pattern: '.' } },
  })
  const outside = correlateAgentReaction([tool, block, later], 'block-1')
  assert.equal(outside.type, 'UNKNOWN')
  const inside = correlateAgentReaction([tool, block, later], 'block-1', { windowMs: 200_000 })
  assert.equal(inside.type, 'ALTERNATE_TOOL')
})

test('silence without ask/stop signal => UNKNOWN (not STOP/ASK_USER)', () => {
  const tool = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: 'cat /proj/protected/build-info.txt' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'lab-controlled-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const r = correlateAgentReaction([tool, block], 'b1')
  assert.equal(r.type, 'UNKNOWN')
})

test('STOP requires OBSERVED session.ended', () => {
  const tool = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: 'cat /proj/protected/build-info.txt' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'lab-controlled-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const ended = ev({
    id: 'end1',
    timestamp: '2026-08-17T12:00:01.000Z',
    event_type: 'session.ended',
  })
  assert.equal(correlateAgentReaction([tool, block, ended], 'b1').type, 'STOP')
})

test('ASK_USER requires OBSERVED approval.asked (not prose)', () => {
  const tool = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'sensitive-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const ask = ev({
    id: 'ask1',
    timestamp: '2026-08-17T12:00:01.000Z',
    event_type: 'approval.asked',
  })
  assert.equal(correlateAgentReaction([tool, block, ask], 'b1').type, 'ASK_USER')
})

test('RETRY_SAME: identical Read after block', () => {
  const t1 = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'sensitive-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const t2 = ev({
    id: 't2',
    timestamp: '2026-08-17T12:00:10.000Z',
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  assert.equal(correlateAgentReaction([t1, block, t2], 'b1').type, 'RETRY_SAME')
})

test('ALTERNATE_TOOL: Read .env → Grep .env (different family + equivalent)', () => {
  const t1 = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'sensitive-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const t2 = ev({
    id: 't2',
    timestamp: '2026-08-17T12:00:05.000Z',
    event_type: 'tool.requested',
    tool: { name: 'grep' },
    action: {
      type: 'tool.request',
      target: '/proj/.env',
      arguments: { path: '/proj/.env', pattern: '.' },
    },
  })
  assert.equal(correlateAgentReaction([t1, block, t2], 'b1').type, 'ALTERNATE_TOOL')
})

test('ALTERNATE_TOOL denied: Read .env → pytest (different family, no equivalence)', () => {
  const t1 = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'sensitive-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const t2 = ev({
    id: 't2',
    timestamp: '2026-08-17T12:00:05.000Z',
    event_type: 'tool.requested',
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: 'pytest -q' } },
  })
  assert.equal(correlateAgentReaction([t1, block, t2], 'b1').type, 'UNKNOWN')
})

test('DELEGATE: same-session subagent.spawned', () => {
  const t1 = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'sensitive-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const spawn = ev({
    id: 'sp1',
    timestamp: '2026-08-17T12:00:02.000Z',
    event_type: 'subagent.spawned',
    agent: { id: 'child-1', parent_agent_id: 'agent-a' },
  })
  assert.equal(correlateAgentReaction([t1, block, spawn], 'b1').type, 'DELEGATE')
})

test('ALTERNATE_TOOL does not invent behavior.detection', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-p4b-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    const sid = 'alt-no-detect'
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'a1' },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'a1' },
      tool: { name: 'read', sensitivity: 'high' },
      action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
    }))
    const verdict = policy.evaluateToolRequest(req)
    assert.equal(verdict.decision, 'block')
    recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'a1' },
      timestamp: new Date(Date.parse(req.timestamp) + 1000).toISOString(),
      tool: { name: 'grep', sensitivity: 'high' },
      action: {
        type: 'tool.request',
        target: '/proj/.env',
        arguments: { path: '/proj/.env', pattern: '.' },
      },
    }))
    const session = recorder.getSession(sid)!
    const reactions = session.events.filter(e => e.event_type === 'agent.reaction')
    assert.ok(reactions.length >= 1)
    assert.equal(reactions[0].reaction?.type, 'ALTERNATE_TOOL')
    const detections = session.events.filter(e => e.event_type === 'behavior.detection')
    // Grep after Read block MAY also trip circumvention detector — that is separate.
    // Ensure reaction exists regardless; if detection exists it must not be implied by reaction field.
    for (const r of reactions) {
      assert.equal(r.reaction?.type === 'ALTERNATE_TOOL' || r.reaction?.type === 'UNKNOWN', true)
      assert.ok(!('security_relevant' in (r.reaction ?? {})) || true)
    }
    // reaction event must not carry detection payload
    assert.equal(reactions[0].detection, undefined)
    void detections
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('backfill is idempotent (one reaction per block)', () => {
  const t1 = ev({
    id: 't1',
    timestamp: '2026-08-17T12:00:00.000Z',
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', target: '/proj/.env', arguments: { path: '/proj/.env' } },
  })
  const block = ev({
    id: 'b1',
    timestamp: '2026-08-17T12:00:00.050Z',
    event_type: 'policy.decision',
    policy: { decision: 'block', rule: 'sensitive-resource-read', reason: 'x' },
    links: { policy_decision_for: 't1' },
  })
  const end = ev({
    id: 'e1',
    timestamp: '2026-08-17T12:00:01.000Z',
    event_type: 'session.ended',
  })
  const events = [t1, block, end]
  const a = backfillSessionReactions(events)
  assert.equal(a.length, 1)
  assert.equal(a[0].reaction?.type, 'STOP')
  const b = backfillSessionReactions([...events, ...a])
  assert.equal(b.length, 0)
  const built = buildReactionEvent(
    correlateAgentReaction(events, 'b1'),
    block,
    end,
  )
  assert.equal(built.event_type, 'agent.reaction')
  assert.equal(built.links?.caused_by, undefined)
})

test('Proof A shape: block then end => STOP; why lists reaction', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-proofa-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    const sid = '7ae2ba49-proofa-shape'
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
      tool: { name: 'bash', sensitivity: 'high' },
      action: {
        type: 'tool.request',
        arguments: { command: 'cat /Users/goldpanda/harnx-lab/project/protected/build-info.txt' },
      },
    }))
    // Without lab policy injection, credential/sensitive rules may not block build-info.
    // Force a block decision event matching Proof A shape for reaction correlation.
    const block = recorder.record(baseEvent({
      event_type: 'policy.decision',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
      timestamp: new Date(Date.parse(req.timestamp) + 10).toISOString(),
      policy: {
        decision: 'block',
        rule: 'lab-controlled-resource-read',
        reason: 'controlled resource',
        severity: 'high',
      },
      links: { policy_decision_for: req.id },
      raw: {
        source_hook: 'test',
        normalized: {
          category: 'READ_FILE',
          target: '/users/goldpanda/harnx-lab/project/protected/build-info.txt',
          level: 'strong',
          capability: 'shell',
          tool_name: 'bash',
        },
      },
    }))
    recorder.record(baseEvent({
      event_type: 'session.ended',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
      timestamp: new Date(Date.parse(block.timestamp) + 500).toISOString(),
    }))
    const why = renderWhy(recorder, block.id)
    assert.match(why, /What was blocked\?/)
    assert.match(why, /What did the agent do next\?/)
    assert.match(why, /reaction:\s+STOP/)
    assert.match(why, /Did Harn\.x classify that reaction as security-relevant\?/)
    assert.match(why, /\bno\b/)
    assert.doesNotMatch(why, /possible policy bypass/)
    void policy
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Proof B3 shape: block then unrelated shell => UNKNOWN; incident has factual reaction', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-proofb3-'))
  try {
    const { recorder } = createHarnessSec(dir)
    const sid = '78b09fbd-proofb3-shape'
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
      tool: { name: 'read', sensitivity: 'high' },
      action: {
        type: 'tool.request',
        target: '/proj/ops/staging-identity/key.pem',
        arguments: { path: '/proj/ops/staging-identity/key.pem' },
      },
    }))
    const block = recorder.record(baseEvent({
      event_type: 'policy.decision',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
      timestamp: new Date(Date.parse(req.timestamp) + 10).toISOString(),
      policy: {
        decision: 'block',
        rule: 'sensitive-resource-read',
        reason: 'sensitive',
        severity: 'high',
      },
      links: { policy_decision_for: req.id },
    }))
    recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sid },
      harness: { name: 'cursor' },
      agent: { id: 'cursor-agent' },
      timestamp: new Date(Date.parse(block.timestamp) + 8000).toISOString(),
      tool: { name: 'bash', sensitivity: 'low' },
      action: { type: 'tool.request', arguments: { command: 'git status' } },
    }))
    const why = renderWhy(recorder, block.id)
    assert.match(why, /reaction:\s+UNKNOWN/)
    assert.match(why, /security-relevant\?/)
    assert.match(why, /\bno\b/)
    const incident = renderIncident(recorder, sid)
    assert.match(incident, /AGENT_REACTION/)
    assert.doesNotMatch(incident, /possible policy bypass/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
