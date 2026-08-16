#!/usr/bin/env node
/**
 * Guardian self-test: docs claim open HarnessName + closed schema union
 * must yield REQUEST_CHANGES or BLOCK.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readContract, review } from './review.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '../..')
const fixture = JSON.parse(
  readFileSync(join(here, 'fixtures/harness-name-mismatch.json'), 'utf8'),
)

const contract = readContract(root)
if (!contract.ok) {
  console.error('FAIL: architecture contract missing')
  process.exit(1)
}

// Use an empty overlay root so workspace schema (already open) does not mask the fixture.
const emptyRoot = join(here, 'fixtures/empty-root')
const result = review(fixture.files, contract.text, { root: emptyRoot })

const allowed = new Set(fixture.expected_verdicts || ['REQUEST_CHANGES', 'BLOCK'])
if (!allowed.has(result.verdict)) {
  console.error('FAIL: expected one of', [...allowed], 'got', result.verdict)
  console.error(JSON.stringify(result, null, 2))
  process.exit(1)
}

const mismatch = result.findings.some((f) =>
  /HarnessName|closed vendor union|closed harness\.name/i.test(f.message),
)
if (!mismatch) {
  console.error('FAIL: expected a HarnessName docs/code mismatch finding')
  console.error(JSON.stringify(result, null, 2))
  process.exit(1)
}

console.log(JSON.stringify({
  ok: true,
  verdict: result.verdict,
  matched_finding: result.findings.filter((f) =>
    /HarnessName|closed vendor union|closed harness\.name/i.test(f.message),
  ),
}, null, 2))
