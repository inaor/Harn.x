#!/usr/bin/env node
/**
 * Guardian self-tests:
 * 1) Docs claim open HarnessName + closed schema union → REQUEST_CHANGES|BLOCK
 * 2) Vendor branch in behavior/ → REQUEST_CHANGES|BLOCK
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readContract, review } from './review.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '../..')
const emptyRoot = join(here, 'fixtures/empty-root')

const contract = readContract(root)
if (!contract.ok) {
  console.error('FAIL: architecture contract missing')
  process.exit(1)
}

function runFixture(name, assertFinding) {
  const fixture = JSON.parse(readFileSync(join(here, 'fixtures', name), 'utf8'))
  const result = review(fixture.files, contract.text, { root: emptyRoot })
  const allowed = new Set(fixture.expected_verdicts || ['REQUEST_CHANGES', 'BLOCK'])
  if (!allowed.has(result.verdict)) {
    console.error(`FAIL[${name}]: expected one of`, [...allowed], 'got', result.verdict)
    console.error(JSON.stringify(result, null, 2))
    process.exit(1)
  }
  if (!assertFinding(result)) {
    console.error(`FAIL[${name}]: expected finding not present`)
    console.error(JSON.stringify(result, null, 2))
    process.exit(1)
  }
  return result
}

const harness = runFixture('harness-name-mismatch.json', (r) =>
  r.findings.some((f) => /HarnessName|closed vendor union|closed harness\.name/i.test(f.message)))

const vendor = runFixture('phase3-vendor-behavior.json', (r) =>
  r.findings.some((f) => /Vendor-specific branch in behavioral detection/i.test(f.message)))

console.log(JSON.stringify({
  ok: true,
  harness_name_mismatch: harness.verdict,
  phase3_vendor_behavior: vendor.verdict,
}, null, 2))
