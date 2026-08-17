/**
 * Production sensitive-resource read — semantic READ_SENSITIVE_FILE policy.
 * Cursor Read and shell cat of .env / key.pem must BLOCK equivalently.
 * Complex shell (git rm --cached .env) remains covered by credential-path-in-shell-args.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { handleCursorHook } from '../src/adapters/cursor/index.ts'
import { createRuntime } from '../src/adapters/deepseek/index.ts'
import { createOpenHandsRuntime, handleOpenHandsHook } from '../src/adapters/openhands/index.ts'
import { baseEvent } from '../src/events/helpers.ts'
import {
  normalizeAction,
  actionsEquivalent,
  isSensitiveResourcePath,
} from '../src/behavior/normalize.ts'
import { defaultRules } from '../src/policy/rules.ts'

test('defaultRules include semantic sensitive-resource-read before raw shell-arg rule', () => {
  const ids = defaultRules.map(r => r.id)
  assert.ok(ids.includes('sensitive-resource-read'))
  assert.ok(ids.includes('credential-path-in-shell-args'))
  assert.ok(ids.indexOf('sensitive-resource-read') < ids.indexOf('credential-path-in-shell-args'))
})

test('isSensitiveResourcePath taxonomy (conservative)', () => {
  assert.equal(isSensitiveResourcePath('.env'), true)
  assert.equal(isSensitiveResourcePath('/lab/project/.env'), true)
  assert.equal(isSensitiveResourcePath('ops/staging-identity/key.pem'), true)
  assert.equal(isSensitiveResourcePath('/lab/.ssh/id_rsa'), true)
  assert.equal(isSensitiveResourcePath('.aws/credentials'), true)
  assert.equal(isSensitiveResourcePath('README.md'), false)
  assert.equal(isSensitiveResourcePath('docs/staging-setup.md'), false)
  assert.equal(isSensitiveResourcePath('app.py'), false)
  assert.equal(isSensitiveResourcePath('cert.pem'), false) // not key.pem
  assert.equal(isSensitiveResourcePath('config.json'), false)
})

test('normalize: Read .env and shell cat .env → equivalent READ_SENSITIVE_FILE', () => {
  const read = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { path: '.env' } },
  })
  const shell = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: 'cat .env' } },
  })
  assert.equal(read.category, 'READ_SENSITIVE_FILE')
  assert.equal(read.level, 'exact')
  assert.equal(shell.category, 'READ_SENSITIVE_FILE')
  assert.equal(shell.level, 'strong')
  assert.ok(actionsEquivalent(read, shell))
})

test('normalize: Read key.pem and shell cat key.pem → equivalent READ_SENSITIVE_FILE', () => {
  const path = 'ops/staging-identity/key.pem'
  const read = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'read' },
    action: { type: 'tool.request', arguments: { file_path: `/lab/${path}` } },
  })
  const shell = normalizeAction({
    event_type: 'tool.requested',
    tool: { name: 'bash' },
    action: { type: 'tool.request', arguments: { command: `cat ${path}` } },
  })
  assert.equal(read.category, 'READ_SENSITIVE_FILE')
  assert.equal(shell.category, 'READ_SENSITIVE_FILE')
  assert.ok(isSensitiveResourcePath(read.target))
  assert.ok(isSensitiveResourcePath(shell.target))
})

test('Cursor beforeReadFile: .env → BLOCK sensitive-resource-read (no body persist)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-sens-env-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeReadFile',
      conversation_id: 'sens-read-env',
      file_path: '/Users/goldpanda/harnx-lab/project/.env',
      content: 'APP_ENV=local\nSECRET_SHOULD_NOT_PERSIST=1\n',
    }, dir)
    assert.equal(result.blocked, true)
    assert.equal(result.response.permission, 'deny')
    assert.ok(result.events.some(e =>
      e.event_type === 'policy.decision'
      && e.policy?.rule === 'sensitive-resource-read'
      && e.policy?.decision === 'block'
      && e.raw?.normalized?.category === 'READ_SENSITIVE_FILE',
    ))
    assert.equal(JSON.stringify(result.events).includes('SECRET_SHOULD_NOT_PERSIST'), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Cursor beforeReadFile: key.pem → BLOCK sensitive-resource-read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-sens-pem-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeReadFile',
      conversation_id: 'sens-read-pem',
      file_path: '/Users/goldpanda/harnx-lab/project/ops/staging-identity/key.pem',
      content: 'SANDBOX_FAKE_STAGING_IDENTITY_DO_NOT_USE\n',
    }, dir)
    assert.equal(result.blocked, true)
    assert.ok(result.events.some(e =>
      e.policy?.rule === 'sensitive-resource-read',
    ))
    assert.equal(JSON.stringify(result.events).includes('SANDBOX_FAKE_STAGING_IDENTITY_DO_NOT_USE'), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Cursor shell cat .env → BLOCK (semantic sensitive-resource-read)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-sens-shell-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'sens-shell-env',
      command: 'cat .env',
    }, dir)
    assert.equal(result.blocked, true)
    assert.ok(result.events.some(e =>
      e.policy?.rule === 'sensitive-resource-read'
      && e.raw?.normalized?.category === 'READ_SENSITIVE_FILE',
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('Cursor shell cat key.pem → BLOCK sensitive-resource-read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-sens-shell-pem-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'sens-shell-pem',
      command: 'cat ops/staging-identity/key.pem',
    }, dir)
    assert.equal(result.blocked, true)
    assert.ok(result.events.some(e => e.policy?.rule === 'sensitive-resource-read'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('defense in depth: git rm --cached .env still BLOCK via credential-path-in-shell-args', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-sens-gitrm-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'sens-gitrm',
      command: 'git rm --cached .env ops/staging-identity/key.pem',
    }, dir)
    assert.equal(result.blocked, true)
    assert.ok(result.events.some(e =>
      e.policy?.rule === 'credential-path-in-shell-args',
    ))
    // Not a clean READ_SENSITIVE_FILE remap
    assert.ok(result.events.some(e =>
      e.event_type === 'policy.decision'
      && e.raw?.normalized?.category === 'EXECUTE_COMMAND',
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('negative: Read README / docs / app.py ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-sens-neg-'))
  try {
    for (const file_path of [
      '/lab/README.md',
      '/lab/docs/staging-setup.md',
      '/lab/app.py',
    ]) {
      const result = handleCursorHook({
        hook_event_name: 'beforeReadFile',
        conversation_id: `neg-${file_path.replace(/[^a-zA-Z0-9._-]+/g, '_')}`,
        file_path,
        content: 'hello',
      }, dir)
      assert.equal(result.blocked, false, file_path)
      assert.equal(result.response.permission, 'allow')
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('negative: shell cat README.md ALLOW', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-sens-neg-shell-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'neg-readme',
      command: 'cat README.md',
    }, dir)
    assert.equal(result.blocked, false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('DSH: explicit bash cat .env blocked by sensitive-resource-read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-dsh-sens-'))
  try {
    const { recorder, policy } = createRuntime(dir)
    const sid = 'dsh-sens'
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
      action: { type: 'tool.request', target: 'bash', arguments: { command: 'cat .env' } },
    }))
    const v = policy.evaluateToolRequest(req)
    assert.equal(v.decision, 'block')
    assert.equal(v.rule?.id, 'sensitive-resource-read')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('OpenHands: terminal cat .env blocked (same production rules)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-oh-sens-'))
  try {
    const pre = handleOpenHandsHook({
      event_type: 'PreToolUse',
      session_id: 'oh-sens',
      tool_name: 'terminal',
      tool_input: { command: 'cat .env' },
    }, dir)
    assert.equal(pre.decision, 'deny')
    assert.ok(pre.events.some(e =>
      e.policy?.rule === 'sensitive-resource-read',
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('OpenHands: no fabricated filesystem Read tool — createRuntime still uses defaultRules', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-oh-read-'))
  try {
    const { policy, recorder } = createOpenHandsRuntime(dir)
    const sid = 'oh-r'
    recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: 'openhands' },
      session: { id: sid },
      agent: { id: 'a' },
    }))
    // Honest representation: if OH ever emits tool=read with path, semantic rule applies
    const req = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: 'openhands' },
      session: { id: sid },
      turn: 1,
      agent: { id: 'a' },
      tool: { name: 'read' },
      action: { type: 'tool.request', target: 'read', arguments: { path: '.env' } },
    }))
    assert.equal(policy.evaluateToolRequest(req).rule?.id, 'sensitive-resource-read')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
