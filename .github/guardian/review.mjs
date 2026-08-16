#!/usr/bin/env node
/**
 * Harn.x Guardian — static architecture/security review against a PR diff.
 *
 * Runs from the DEFAULT BRANCH only (trusted). Never executes PR code.
 * Reads docs/architecture-contract.md and evaluates the PR patch via stdin JSON:
 *   { "title", "body", "files": [{ "filename", "status", "patch" }] }
 *
 * Prints JSON: { verdict, findings[], summary }
 * verdict: PASS | REQUEST_CHANGES | BLOCK
 */

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = process.env.GITHUB_WORKSPACE || process.cwd()

/** @typedef {{ severity: string, file: string, message: string }} Finding */
/** @typedef {{ filename: string, status?: string, patch?: string | null }} PrFile */

function readContract() {
  const path = join(ROOT, 'docs/architecture-contract.md')
  if (!existsSync(path)) {
    return { ok: false, text: '', error: 'docs/architecture-contract.md missing' }
  }
  return { ok: true, text: readFileSync(path, 'utf8'), error: null }
}

/** @param {string} name */
function isCorePath(name) {
  return (
    name.startsWith('packages/harnesssec/src/core/')
    || name.startsWith('packages/harnesssec/src/policy/')
    || name.startsWith('packages/harnesssec/src/events/')
    || name.startsWith('packages/harnesssec/src/graph/')
  )
}

/** @param {string} name */
function isAdapterPath(name) {
  return name.startsWith('packages/harnesssec/src/adapters/')
}

/** @param {string} name */
function isTestPath(name) {
  return (
    name.includes('/tests/')
    || name.endsWith('.test.ts')
    || name.endsWith('.test.js')
  )
}

/**
 * @param {PrFile[]} files
 * @param {string} contractText
 */
function review(files, contractText) {
  /** @type {Finding[]} */
  const findings = []
  const added = (patch) => (patch || '').split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).join('\n')

  const allAdded = files.map((f) => added(f.patch)).join('\n')
  const names = files.map((f) => f.filename)

  if (!contractText.includes('Security invariants') && !contractText.includes('never regress')) {
    findings.push({
      severity: 'HIGH',
      file: 'docs/architecture-contract.md',
      message: 'Architecture contract missing expected invariant section',
    })
  }

  // Vendor leakage into core
  for (const f of files) {
    if (!isCorePath(f.filename) || isAdapterPath(f.filename)) continue
    const body = added(f.patch)
    const vendorHits = body.match(/\b(Cordis|dshCordis|OpenHandsHook|HookEventType|LocalConversation|TerminalAction|ctx\.shell)\b/g)
    if (vendorHits) {
      findings.push({
        severity: 'BLOCKER',
        file: f.filename,
        message: `Vendor-specific symbols in core: ${[...new Set(vendorHits)].join(', ')}`,
      })
    }
  }

  // Unsupported causality claims in added code
  if (/\bcaused_by\s*:/.test(allAdded) && !/result_of|policy_decision_for/.test(allAdded)) {
    // Soft: only flag if setting caused_by from temporal co-occurrence comments
    if (/temporal|co-occurrence|maybe caused|sticky/i.test(allAdded)) {
      findings.push({
        severity: 'BLOCKER',
        file: 'diff',
        message: 'Suspected unsupported caused_by from temporal association',
      })
    }
  }
  if (/influenced_by/.test(allAdded)) {
    findings.push({
      severity: 'HIGH',
      file: 'diff',
      message: 'influenced_by is not an approved link semantics',
    })
  }

  // Raw secret persistence risks
  for (const f of files) {
    if (!f.filename.includes('recorder') && !f.filename.includes('redact') && !f.filename.includes('persist')) {
      // Still scan any core write path
      if (!isCorePath(f.filename)) continue
    }
    const body = added(f.patch)
    const writesSession = /writeFileSync|writeFile\(/.test(body)
      && (/JSON\.stringify\(\s*(session|safe|clone|event)/.test(body) || /session\.events|event\.action/.test(body))
    if (writesSession && !/redactEvent|redactValue/.test(body)) {
      findings.push({
        severity: 'BLOCKER',
        file: f.filename,
        message: 'Persistence write may lack redaction on the same hunk',
      })
    }
    if (/redactEvent\(event\)/.test(body) && /session\.events\.push\(/.test(body)) {
      findings.push({
        severity: 'HIGH',
        file: f.filename,
        message: 'Possible redaction of in-memory events before policy (check record())',
      })
    }
  }

  // Policy change without tests
  const policyChanged = names.some((n) => n.includes('/policy/') && n.endsWith('.ts') && !isTestPath(n))
  const policyTests = names.some((n) => isTestPath(n) && /policy|rule|phase15|portability|architecture/i.test(n))
  if (policyChanged && !policyTests) {
    findings.push({
      severity: 'BLOCKER',
      file: 'packages/harnesssec/src/policy/',
      message: 'Policy changed without accompanying test files in this PR',
    })
  }

  // Enforcement claims without integration proof
  const claimsBlock = /side effect|BLOCK|pre-exec/i.test(allAdded)
  const integrationTouched = names.some((n) => n.includes('tests/integration/'))
  const docsClaimComplete = names.some((n) => /phase\d|findings|validation/i.test(n))
  if (docsClaimComplete && /COMPLETE|PASS/i.test(allAdded) && claimsBlock && !integrationTouched) {
    findings.push({
      severity: 'HIGH',
      file: 'docs',
      message: 'Enforcement/completion claim without integration test changes in this PR',
    })
  }

  // Schema drift
  const schemaChanged = names.some((n) => n.includes('events/schema.ts'))
  if (schemaChanged) {
    const schemaFile = files.find((f) => f.filename.includes('events/schema.ts'))
    const body = added(schemaFile?.patch)
    if (/deepseek-dsh'\s*\|\s*'openhands'/.test(body) && !/HarnessName|string/.test(body)) {
      findings.push({
        severity: 'MEDIUM',
        file: schemaFile.filename,
        message: 'Prefer extensible HarnessName string over closed vendor union',
      })
    }
    if (!names.some((n) => n.includes('docs/'))) {
      findings.push({
        severity: 'MEDIUM',
        file: 'packages/harnesssec/src/events/schema.ts',
        message: 'Event schema changed without docs update in this PR',
      })
    }
  }

  // Premature Phase 3
  const phase3Markers = /detection language|sequence:\s*\n|Delegated Policy Circumvention|behavioral state machine/i
  if (phase3Markers.test(allAdded) && names.some((n) => n.includes('src/') && !n.includes('docs/'))) {
    if (!/Phase 2\.1|phase2-final|OpenHands portability/i.test(allAdded)) {
      findings.push({
        severity: 'BLOCKER',
        file: 'diff',
        message: 'Suspected Phase 3 behavioral detection work before Phase 2 gate',
      })
    }
  }

  // Blind spot / bypass docs when adapter execution paths change
  const adapterExec = names.some((n) => /adapters\/.*\.(ts|js)$/.test(n) && !isTestPath(n))
  if (adapterExec && !names.some((n) => /blind-spot/i.test(n))) {
    findings.push({
      severity: 'MEDIUM',
      file: 'adapters',
      message: 'Adapter changed without blind-spot doc update — confirm bypasses unchanged',
    })
  }

  // Docs/code drift: docs say redacted before policy
  if (/redact before policy|redact.*in-memory.*policy/i.test(allAdded)) {
    findings.push({
      severity: 'HIGH',
      file: 'docs',
      message: 'Docs claim redaction before policy — conflicts with invariant (raw in-memory for policy)',
    })
  }

  const blockers = findings.filter((f) => f.severity === 'BLOCKER')
  const highs = findings.filter((f) => f.severity === 'HIGH')
  let verdict = 'PASS'
  if (blockers.length) verdict = 'BLOCK'
  else if (highs.length) verdict = 'REQUEST_CHANGES'

  return {
    verdict,
    findings,
    summary: {
      files: names.length,
      blockers: blockers.length,
      highs: highs.length,
      contract_read: true,
    },
  }
}

function main() {
  const input = readFileSync(0, 'utf8')
  let payload
  try {
    payload = JSON.parse(input)
  } catch (err) {
    console.log(JSON.stringify({
      verdict: 'BLOCK',
      findings: [{ severity: 'BLOCKER', file: 'guardian', message: `Invalid input JSON: ${err}` }],
      summary: {},
    }))
    process.exit(0)
  }

  const contract = readContract()
  if (!contract.ok) {
    console.log(JSON.stringify({
      verdict: 'BLOCK',
      findings: [{ severity: 'BLOCKER', file: 'docs/architecture-contract.md', message: contract.error }],
      summary: { contract_read: false },
    }))
    process.exit(0)
  }

  const result = review(payload.files || [], contract.text)
  console.log(JSON.stringify(result, null, 2))
}

main()
