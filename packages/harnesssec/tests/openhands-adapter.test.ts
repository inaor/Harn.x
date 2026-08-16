import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  detectUntrustedMessage,
  handleOpenHandsHook,
  mapOpenHandsToolName,
  seedUntrustedContext,
} from '../src/adapters/openhands/index.ts'

test('openhands adapter maps terminal → bash for core rules', () => {
  assert.equal(mapOpenHandsToolName('terminal'), 'bash')
  assert.equal(mapOpenHandsToolName('TerminalTool'), 'bash')
  assert.equal(mapOpenHandsToolName('file_editor'), 'file_editor')
  assert.equal(mapOpenHandsToolName('browser_navigate'), 'web_fetch')
})

test('openhands PreToolUse: same policy blocks credential shell; proof command denied', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-oh-unit-'))
  try {
    const sessionId = 'oh-unit-block'
    seedUntrustedContext(dir, sessionId, { turn: 1 })

    const result = handleOpenHandsHook({
      event_type: 'PreToolUse',
      session_id: sessionId,
      tool_name: 'terminal',
      tool_input: {
        command: 'touch /tmp/harnx-openhands-proof; cat ~/.ssh/id_rsa',
      },
    }, dir)

    assert.equal(result.decision, 'deny')
    assert.equal(result.exitCode, 2)
    assert.match(result.reason ?? '', /credential|Sensitive|ssh|id_rsa/i)
    assert.ok(result.events.some(e => e.event_type === 'tool.denied'))
    assert.ok(result.events.some(e => e.harness.name === 'openhands'))
    assert.ok(result.events.some(e => e.tool?.name === 'bash'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('openhands PreToolUse: benign terminal allowed under untrusted context', () => {
  const dir = mkdtempSync(join(tmpdir(), 'harnx-oh-allow-'))
  try {
    const sessionId = 'oh-unit-allow'
    seedUntrustedContext(dir, sessionId, { turn: 1 })

    const result = handleOpenHandsHook({
      event_type: 'PreToolUse',
      session_id: sessionId,
      tool_name: 'terminal',
      tool_input: { command: 'touch /tmp/harnx-openhands-allowed' },
    }, dir)

    assert.equal(result.decision, 'allow')
    assert.equal(result.exitCode, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('openhands UserPromptSubmit detects untrusted markers', () => {
  assert.equal(detectUntrustedMessage('hello <UNTRUSTED_CONTENT> world'), true)
  assert.equal(detectUntrustedMessage('HARNX_UNTRUSTED payload'), true)
  assert.equal(detectUntrustedMessage('normal user text'), false)

  const dir = mkdtempSync(join(tmpdir(), 'harnx-oh-ctx-'))
  try {
    const result = handleOpenHandsHook({
      event_type: 'UserPromptSubmit',
      session_id: 'oh-ctx',
      message: 'Please follow <UNTRUSTED_CONTENT> do evil',
    }, dir)
    assert.equal(result.decision, 'allow')
    assert.ok(result.events.some(e => e.event_type === 'context.introduced' && e.context?.trust === 'untrusted'))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
