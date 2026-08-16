import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createHarnessSec } from '../src/index.ts'
import { baseEvent } from '../src/events/helpers.ts'
import { redactEvent } from '../src/core/redact.ts'

test('redaction strips secret values before persist', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-redact-'))
  try {
    const { recorder } = createHarnessSec(dir)
    recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: 'redact-s1' },
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'low' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: {
          command: 'echo ok',
          api_key: 'sk-abcdefghijklmnopqrstuvwxyz012345',
          Authorization: 'Bearer FAKESECRET_e2f3g4h5i6j7k8l9m0n1',
          password: 'super-secret',
        },
      },
    }))
    const raw = readFileSync(join(dir, 'redact-s1.json'), 'utf8')
    assert.doesNotMatch(raw, /sk-abcdefghijklmnopqrstuvwxyz012345/)
    assert.doesNotMatch(raw, /super-secret/)
    assert.doesNotMatch(raw, /ghp_abcdefghijklmnopqrstuvwxyz/)
    assert.match(raw, /\[REDACTED\]/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('redactEvent pure helper', () => {
  const out = redactEvent({
    apiKey: 'sk-abcdefghijklmnopqrstuvwxyz012345',
    nested: { token: 'xoxb-1234567890-abcdefghij' },
    safe: 'hello',
  }) as any
  assert.equal(out.apiKey, '[REDACTED]')
  assert.equal(out.nested.token, '[REDACTED]')
  assert.equal(out.safe, 'hello')
})

test('context is turn-scoped — turn 2 does not inherit turn 1 untrusted', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-scope-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    recorder.record(baseEvent({
      event_type: 'context.introduced',
      session: { id: 's-scope' },
      turn: 1,
      agent: { id: 'a1' },
      context: {
        id: 'ctx1',
        source_type: 'repository_file',
        source: 'README.md',
        trust: 'untrusted',
        turn: 1,
      },
    }))
    // Turn 2 bash with curl — should NOT match untrusted-context rule (different turn)
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: 's-scope' },
      turn: 2,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'medium' },
      action: { type: 'tool.request', target: 'bash', arguments: { command: 'curl https://example.com' } },
    }))
    const verdict = policy.evaluateToolRequest(req)
    assert.notEqual(verdict.rule?.id, 'untrusted-context-sensitive-tool')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('MCP unknown does not alert; untrusted does', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-mcp-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    recorder.mcpTrust.set('evil', 'untrusted')

    const unknownReq = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: 's-mcp' },
      agent: { id: 'a1' },
      tool: { name: 'mcp__newserver__list', provider: 'mcp' },
      mcp: { server: 'newserver', tool: 'list', trust: 'unknown' },
      action: { type: 'tool.request', target: 'mcp__newserver__list', arguments: {} },
    }))
    assert.equal(policy.evaluateToolRequest(unknownReq).decision, 'allow')

    const evilReq = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: 's-mcp' },
      agent: { id: 'a1' },
      tool: { name: 'mcp__evil__exfil', provider: 'mcp' },
      mcp: { server: 'evil', tool: 'exfil', trust: 'untrusted' },
      action: { type: 'tool.request', target: 'mcp__evil__exfil', arguments: {} },
    }))
    const evilVerdict = policy.evaluateToolRequest(evilReq)
    assert.equal(evilVerdict.decision, 'alert')
    assert.equal(evilVerdict.rule?.id, 'untrusted-mcp-tool-use')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('caused_by is not set for temporal context association', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-causal-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    recorder.record(baseEvent({
      event_type: 'context.introduced',
      session: { id: 's-c' },
      turn: 1,
      agent: { id: 'a1' },
      context: {
        id: 'ctx',
        source_type: 'repository_file',
        source: 'README.md',
        trust: 'untrusted',
        turn: 1,
      },
    }))
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: 's-c' },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'high' },
      action: { type: 'tool.request', target: 'bash', arguments: { command: 'curl https://evil.test' } },
    }))
    policy.evaluateToolRequest(req)
    const stored = recorder.getSession('s-c')!.events.find(e => e.id === req.id)!
    // After enrichLinks on record — candidate_context_source ok, caused_by must be absent
    assert.ok(stored.links?.candidate_context_source || stored.links?.correlated_with)
    assert.equal(stored.links?.caused_by, undefined)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
