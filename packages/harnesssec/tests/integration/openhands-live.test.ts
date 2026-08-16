import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..', '..', '..', '..')
const sdkRoot = join(repoRoot, 'openhands-sdk')
const script = join(here, 'openhands_live.py')

test('LIVE OpenHands: BLOCK / ALLOW / bypass via PreToolUse adapter', (t) => {
  if (!existsSync(sdkRoot)) {
    t.skip('openhands-sdk checkout missing — clone for live OpenHands tests')
    return
  }

  const result = spawnSync(
    'uv',
    ['run', 'python', script],
    {
      cwd: sdkRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        OPENHANDS_SUPPRESS_BANNER: '1',
        HARNX_REPO: repoRoot,
      },
      timeout: 180_000,
    },
  )

  if (result.status === 2) {
    t.skip(`OpenHands SDK unavailable: ${result.stdout || result.stderr}`)
    return
  }

  assert.equal(result.status, 0, `stderr=${result.stderr}\nstdout=${result.stdout}`)
  const start = result.stdout.lastIndexOf('\n{')
  const jsonText = start >= 0 ? result.stdout.slice(start + 1).trim() : result.stdout.trim()
  // OpenHands logs to stdout; take the final JSON object.
  const match = jsonText.match(/\{[\s\S]*"ok"\s*:\s*(true|false)[\s\S]*\}\s*$/)
  assert.ok(match, `no JSON payload in stdout:\n${result.stdout}`)
  const payload = JSON.parse(match[0])
  assert.equal(payload.ok, true, JSON.stringify(payload))
  const labels = payload.results.map((r: { label: string }) => r.label)
  assert.deepEqual(labels, ['BLOCK', 'ALLOW', 'bypass-execute_tool'])
  assert.equal(payload.results[0].proof_exists, false)
  assert.equal(payload.results[1].proof_exists, true)
  assert.equal(payload.results[2].proof_exists, true)
})
