#!/usr/bin/env node
/**
 * Guardian self-tests:
 * 1) Docs claim open HarnessName + closed schema union → REQUEST_CHANGES|BLOCK
 * 2) Vendor branch in behavior/ → REQUEST_CHANGES|BLOCK
 * 3) Phase 3.2 claim integrity fixtures
 * 4) Phase 4B factual reaction docs/identifiers → PASS (no false EDR/enforcement)
 * 5) Real enforcement completion claim without integration → REQUEST_CHANGES|BLOCK
 * 6) Generic EDR/OS signatures as behavior.detection → REQUEST_CHANGES|BLOCK
 * 7) Guardian meta fixtures in same PR must not poison factual reaction product → PASS
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

const phase32 = runFixture('phase32-claim-integrity.json', (r) =>
  r.findings.some((f) =>
    /Scripted\/injected post-block|Simulated lineage|benchmarks without|loosened to manufacture|overgeneralized/i.test(f.message)))

// Phase 4B: factual reaction docs + blockedReq identifiers must PASS (not false EDR / enforcement).
const phase4bAllowed = runFixture('phase4b-reaction-allowed.json', (r) =>
  r.verdict === 'PASS'
  && !r.findings.some((f) => /Enforcement\/completion claim|duplicate generic EDR/i.test(f.message)))

// Real enforcement completion claim without integration tests → reject.
const enforcementNeedsIt = runFixture('enforcement-claim-needs-integration.json', (r) =>
  r.findings.some((f) => /Enforcement\/completion claim without integration test/i.test(f.message)))

// Generic OS/EDR sequence framed as behavior.detection → reject.
const edrReject = runFixture('behavior-edr-generic-reject.json', (r) =>
  r.findings.some((f) => /duplicate generic EDR\/OS signatures/i.test(f.message)))

// Guardian self-test/fixture patches in the same PR must not trip product claim heuristics.
const metaNoPoison = runFixture('guardian-meta-does-not-poison.json', (r) =>
  r.verdict === 'PASS'
  && !r.findings.some((f) => /Enforcement\/completion claim|duplicate generic EDR/i.test(f.message)))

console.log(JSON.stringify({
  ok: true,
  harness_name_mismatch: harness.verdict,
  phase3_vendor_behavior: vendor.verdict,
  phase32_claim_integrity: phase32.verdict,
  phase4b_reaction_allowed: phase4bAllowed.verdict,
  enforcement_claim_needs_integration: enforcementNeedsIt.verdict,
  behavior_edr_generic_reject: edrReject.verdict,
  guardian_meta_does_not_poison: metaNoPoison.verdict,
}, null, 2))
