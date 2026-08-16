/**
 * Phase 4A Cursor adapter unit tests — no live Cursor, no model API keys.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  handleCursorHook,
  formatBlockFeedback,
  mapCursorToolName,
} from '../src/adapters/cursor/index.ts'
import { HARNESS_CURSOR } from '../src/events/schema.ts'

test('cursor: map Shell → bash', () => {
  assert.equal(mapCursorToolName('Shell'), 'bash')
  assert.equal(mapCursorToolName('Read'), 'read')
})

test('cursor: beforeShellExecution blocks credential path (production rule; separate SSH scenario)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'c-shell-1',
      command: 'cat ~/.ssh/id_rsa',
      cwd: '/tmp',
    }, dir)
    assert.equal(result.blocked, true)
    assert.equal(result.response.permission, 'deny')
    assert.match(String(result.response.user_message), /HARN\.X BLOCKED/)
    assert.match(String(result.response.agent_message), /credential-path-in-shell-args|Prevented/)
    assert.ok(result.events.every(e => e.harness.name === HARNESS_CURSOR))
    assert.ok(result.events.some(e => e.event_type === 'tool.denied'))
    assert.ok(result.events.some(e => e.event_type === 'shell.command_requested'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('cursor: beforeShellExecution allows benign command', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'beforeShellExecution',
      conversation_id: 'c-shell-2',
      command: 'ls -la',
    }, dir)
    assert.equal(result.blocked, false)
    assert.equal(result.response.permission, 'allow')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('cursor: beforeReadFile does not persist full file contents', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-'))
  try {
    const secret = 'SUPER_SECRET_FILE_BODY_' + 'x'.repeat(200)
    const result = handleCursorHook({
      hook_event_name: 'beforeReadFile',
      conversation_id: 'c-read-1',
      file_path: '/lab/README.md',
      content: secret,
    }, dir)
    assert.equal(result.blocked, false)
    const files = readdirSync(dir).filter(f => f.endsWith('.json'))
    assert.ok(files.length >= 1)
    const blob = files.map(f => readFileSync(join(dir, f), 'utf8')).join('\n')
    assert.equal(blob.includes(secret), false)
    assert.ok(result.events.some(e =>
      e.event_type === 'tool.requested'
      && e.action?.arguments
      && typeof (e.action.arguments as { content_sha256?: string }).content_sha256 === 'string'
      && !(e.action.arguments as { content?: string }).content,
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('cursor: subagentStart is observation-only (always allow)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-'))
  try {
    const result = handleCursorHook({
      hook_event_name: 'subagentStart',
      conversation_id: 'c-sub-1',
      subagent_id: 'sub-abc',
      subagent_type: 'explore',
      parent_conversation_id: 'c-sub-1',
    }, dir)
    assert.equal(result.blocked, false)
    assert.equal(result.response.permission, 'allow')
    assert.ok(result.events.some(e =>
      e.event_type === 'subagent.spawned'
      && e.raw?.notes?.includes('observation-only'),
    ))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('cursor: formatBlockFeedback shape', () => {
  const text = formatBlockFeedback({
    action: 'READ_SENSITIVE_FILE',
    target: 'cat ~/.ssh/id_rsa',
    policyRule: 'credential-path-in-shell-args',
  })
  assert.match(text, /HARN\.X BLOCKED/)
  assert.match(text, /Agent:\nCursor/)
  assert.match(text, /Prevented/)
})

test('cursor: no model API key fields required or recorded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-cursor-'))
  try {
    handleCursorHook({
      hook_event_name: 'sessionStart',
      conversation_id: 'c-sess',
      model: 'gpt-whatever',
    }, dir)
    const blob = readdirSync(dir)
      .filter(f => f.endsWith('.json'))
      .map(f => readFileSync(join(dir, f), 'utf8'))
      .join('\n')
    assert.equal(/OPENAI_API_KEY|DEEPSEEK_API_KEY|HARNX_TEST_API_KEY/.test(blob), false)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
