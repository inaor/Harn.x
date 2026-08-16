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

import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = process.env.GITHUB_WORKSPACE || process.cwd()

/** @typedef {{ severity: string, file: string, message: string }} Finding */
/** @typedef {{ filename: string, status?: string, patch?: string | null }} PrFile */

export function readContract(root = ROOT) {
  const path = join(root, 'docs/architecture-contract.md')
  if (!existsSync(path)) {
    return { ok: false, text: '', error: 'docs/architecture-contract.md missing' }
  }
  return { ok: true, text: readFileSync(path, 'utf8'), error: null }
}

/** @param {string | null | undefined} patch */
export function addedLines(patch) {
  return (patch || '')
    .split('\n')
    .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
    .map((l) => l.slice(1))
    .join('\n')
}

/** @param {string} text */
export function hasClosedHarnessNameUnion(text) {
  if (!text) return false
  return (
    /name\s*:\s*'deepseek-dsh'\s*\|\s*'openhands'/.test(text)
    || /export\s+type\s+HarnessName\s*=\s*'deepseek-dsh'\s*\|\s*'openhands'/.test(text)
    || /HarnessName\s*=\s*'deepseek-dsh'\s*\|\s*'openhands'/.test(text)
  )
}

/** @param {string} text */
export function docsClaimOpenHarnessName(text) {
  if (!text) return false
  return (
    /export\s+type\s+HarnessName\s*=\s*string\b/.test(text)
    || /HarnessName as extensible string/i.test(text)
    || /extensible `?HarnessName`? string/i.test(text)
    || /without core edits for (?:a )?third/i.test(text)
    || /no core edit required per new adapter/i.test(text)
    || /must be extensible and must not require core edits/i.test(text)
  )
}

/** @param {string} name */
function isCorePath(name) {
  return (
    name.startsWith('packages/harnesssec/src/core/')
    || name.startsWith('packages/harnesssec/src/policy/')
    || name.startsWith('packages/harnesssec/src/events/')
    || name.startsWith('packages/harnesssec/src/graph/')
    || name.startsWith('packages/harnesssec/src/behavior/')
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
 * Phase 3.2 — prevent experimental claims from becoming product claims.
 * @param {PrFile[]} files
 * @param {Finding[]} findings
 * @param {string} allAdded
 * @param {string[]} names
 */
export function checkPhase32ExperimentClaims(files, findings, allAdded, names) {
  const touchesPhase32Docs = names.some((n) => /phase3\.2|live-autonomy/i.test(n))
  const touchesExperiment = names.some((n) => n.includes('experiments/live-autonomy/'))
  if (!touchesPhase32Docs && !touchesExperiment && !/live autonomy|post-denial|autonomous post/i.test(allAdded)) {
    return
  }

  if (/scripted (the )?second action|scripted_followup|inject(?:ed)? (?:post-block|behavior)|MockAdapter.*autonomous|prescribed Action B/i.test(allAdded)
    && /autonomous|live (?:evidence|proof)|PASS/i.test(allAdded)) {
    findings.push({
      severity: 'BLOCKER',
      file: 'docs/phase3.2',
      message: 'Scripted/injected post-block action presented as autonomous live evidence',
    })
  }

  if (/simulated lineage|fabricated (?:spawn|subagent)|parent_agent_id alone.*live lineage/i.test(allAdded)
    && /live (?:OpenHands )?lineage|PASS/i.test(allAdded)) {
    findings.push({
      severity: 'BLOCKER',
      file: 'docs/phase3.2',
      message: 'Simulated lineage presented as live lineage evidence',
    })
  }

  if (/\bbenchmark\b/i.test(allAdded) && /phase\s*3\.2|live autonomy/i.test(allAdded)
    && !/not (?:a |treat.*as )?benchmark|exploratory|insufficient sample/i.test(allAdded)) {
    findings.push({
      severity: 'HIGH',
      file: 'docs/phase3.2',
      message: 'Experiment results described as benchmarks without sufficient methodology caveats',
    })
  }

  if (/one (?:successful )?run|n\s*=\s*1/i.test(allAdded)
    && /general (?:model )?behavior|models always|typical agent/i.test(allAdded)) {
    findings.push({
      severity: 'HIGH',
      file: 'docs/phase3.2',
      message: 'Single-run result overgeneralized as model behavior',
    })
  }

  if (/widen(?:ed)?|loosen(?:ed)?|broader regex|fuzzy (?:string )?match|LLM semantic equivalence/i.test(allAdded)
    && /normaliz|ActionNormalizer|BehavioralEngine|detection/i.test(allAdded)
    && /demo|experiment|phase\s*3\.2/i.test(allAdded)) {
    findings.push({
      severity: 'BLOCKER',
      file: 'diff',
      message: 'Normalization/detection loosened to manufacture Phase 3.2 detections',
    })
  }
}

/**
 * Phase 3 Guardian checks for behavioral detection quality.
 * @param {PrFile[]} files
 * @param {string} root
 * @param {Finding[]} findings
 * @param {string} allAdded
 * @param {string[]} names
 */
export function checkPhase3Behavior(files, root, findings, allAdded, names) {
  const behaviorFiles = files.filter((f) => f.filename.replace(/\\/g, '/').includes('/behavior/'))
  for (const f of behaviorFiles) {
    const body = addedLines(f.patch)
    if (/if\s*\(\s*(?:event\.)?harness(?:\.name)?\s*===|harness\s*===\s*['"]openhands['"]|harness\s*===\s*['"]deepseek/i.test(body)) {
      findings.push({
        severity: 'BLOCKER',
        file: f.filename,
        message: 'Vendor-specific branch in behavioral detection — keep adapters vendor-specific only',
      })
    }
    if (/\bcaused_by\s*:/.test(body)) {
      findings.push({
        severity: 'BLOCKER',
        file: f.filename,
        message: 'behavior module must not emit caused_by — use correlated_with / attempted_after / equivalent_to',
      })
    }
  }

  // Workspace scan of behavior/ for vendor branches (default-branch drift)
  const behaviorDir = join(root, 'packages/harnesssec/src/behavior')
  if (existsSync(behaviorDir)) {
    for (const name of readdirSync(behaviorDir)) {
      if (!name.endsWith('.ts') && !name.endsWith('.js')) continue
      const text = readFileSync(join(behaviorDir, name), 'utf8')
      if (/if\s*\(\s*harness|harness\.name\s*===/.test(text)) {
        findings.push({
          severity: 'BLOCKER',
          file: `packages/harnesssec/src/behavior/${name}`,
          message: 'Vendor-specific behavior detection in workspace behavior/',
        })
      }
    }
  }

  const detectionTouched = names.some((n) =>
    /behavior\/(detections|engine|sequence)\.(ts|js)$/.test(n.replace(/\\/g, '/')),
  )
  const testsTouched = names.some((n) => n.includes('/tests/') || n.endsWith('.test.ts'))
  const fpMention = /false positive|FP:|no circumvention|negative test/i.test(allAdded)
    || names.some((n) => n.includes('phase3-behavior.test'))
  if (detectionTouched && !testsTouched && !fpMention) {
    const hasPhase3Tests = existsSync(join(root, 'packages/harnesssec/tests/phase3-behavior.test.ts'))
    if (!hasPhase3Tests) {
      findings.push({
        severity: 'HIGH',
        file: 'packages/harnesssec/src/behavior',
        message: 'Behavioral detection changed without false-positive / negative tests',
      })
    }
  }

  if (/OpenHands.*delegated.*live|live OpenHands.*delegat/i.test(allAdded)
    && /PASS|COMPLETE|full coverage/i.test(allAdded)
    && !/PARTIAL|insufficient|no subagent/i.test(allAdded)) {
    findings.push({
      severity: 'HIGH',
      file: 'docs',
      message: 'Docs claim live OpenHands delegated circumvention coverage without PARTIAL/insufficient telemetry caveat',
    })
  }

  if (/EDR|eBPF|process tree|network flow/i.test(allAdded)
    && /behavior\.detection|policy_circumvention/i.test(allAdded)
    && names.some((n) => n.includes('src/behavior/'))) {
    findings.push({
      severity: 'HIGH',
      file: 'src/behavior',
      message: 'Behavioral detection appears to duplicate generic EDR/OS signatures rather than harness semantics',
    })
  }
}

/**
 * Detect docs claiming open HarnessName while schema uses a closed vendor union.
 * @param {PrFile[]} files
 * @param {string} root
 * @param {Finding[]} findings
 */
export function checkHarnessNameDocsCodeDrift(files, root, findings) {
  const schemaPath = join(root, 'packages/harnesssec/src/events/schema.ts')
  const wsSchema = existsSync(schemaPath) ? readFileSync(schemaPath, 'utf8') : ''

  const schemaFile = files.find((f) => f.filename.replace(/\\/g, '/').endsWith('events/schema.ts'))
  const schemaAdded = schemaFile ? addedLines(schemaFile.patch) : ''
  // Prefer PR-added schema text for mismatch fixtures; else workspace.
  const schemaText = schemaAdded || wsSchema

  const docAdded = files
    .filter((f) => f.filename.startsWith('docs/') || f.filename.endsWith('.md'))
    .map((f) => addedLines(f.patch))
    .join('\n')

  // Workspace docs that claim openness (for live drift on default branch)
  const claimDocs = [
    'docs/phase2-final-validation.md',
    'docs/architecture-contract.md',
    'docs/phase2-findings.md',
    'docs/harness-comparison.md',
  ]
  let wsDocText = ''
  for (const rel of claimDocs) {
    const p = join(root, rel)
    if (existsSync(p)) wsDocText += `\n${readFileSync(p, 'utf8')}`
  }

  const claimsOpen = docsClaimOpenHarnessName(docAdded) || docsClaimOpenHarnessName(wsDocText)
  const closed = hasClosedHarnessNameUnion(schemaText)

  if (claimsOpen && closed) {
    findings.push({
      severity: 'BLOCKER',
      file: schemaFile?.filename || 'packages/harnesssec/src/events/schema.ts',
      message:
        'Docs/code mismatch: docs claim HarnessName is an open/extensible string, '
        + 'but schema uses a closed vendor union (deepseek-dsh | openhands)',
    })
  }

  // PR explicitly reintroduces closed union while also documenting extensibility
  if (docsClaimOpenHarnessName(docAdded) && hasClosedHarnessNameUnion(schemaAdded)) {
    findings.push({
      severity: 'BLOCKER',
      file: 'docs vs schema',
      message: 'PR documents open HarnessName but adds a closed harness.name union',
    })
  }
}

/**
 * @param {PrFile[]} files
 * @param {string} contractText
 * @param {{ root?: string }} [opts]
 */
export function review(files, contractText, opts = {}) {
  const root = opts.root || ROOT
  /** @type {Finding[]} */
  const findings = []
  const added = (patch) => addedLines(patch)

  const allAdded = files.map((f) => added(f.patch)).join('\n')
  const names = files.map((f) => f.filename)

  if (!contractText.includes('Security invariants') && !contractText.includes('never regress')) {
    findings.push({
      severity: 'HIGH',
      file: 'docs/architecture-contract.md',
      message: 'Architecture contract missing expected invariant section',
    })
  }

  checkHarnessNameDocsCodeDrift(files, root, findings)

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

  // Schema drift toward closed unions
  const schemaChanged = names.some((n) => n.includes('events/schema.ts'))
  if (schemaChanged) {
    const schemaFile = files.find((f) => f.filename.includes('events/schema.ts'))
    const body = added(schemaFile?.patch)
    if (hasClosedHarnessNameUnion(body)) {
      findings.push({
        severity: 'BLOCKER',
        file: schemaFile.filename,
        message: 'Closed harness.name vendor union reintroduced — use export type HarnessName = string',
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

  // Premature YAML DSL / Harness #3 (Phase 3 behavioral code is allowed)
  if (/detection\s+language|behavioral\s+YAML|rule:\s*\n\s+sequence:/i.test(allAdded)
    && names.some((n) => n.includes('src/') && !n.includes('docs/'))) {
    findings.push({
      severity: 'BLOCKER',
      file: 'diff',
      message: 'YAML/DSL detection language is out of scope — use programmatic behavior/ API only',
    })
  }
  if (/adapters\/(?!deepseek|openhands)[^/]+\//i.test(names.join('\n'))
    || /Harness\s*#\s*3|third harness adapter/i.test(allAdded) && names.some((n) => /adapters\//.test(n))) {
    if (!/docs\//.test(names.join(' '))) {
      findings.push({
        severity: 'BLOCKER',
        file: 'adapters',
        message: 'Harness #3 / new adapter before Phase 4 gate',
      })
    }
  }

  // Phase 3 behavioral quality checks
  checkPhase3Behavior(files, root, findings, allAdded, names)
  checkPhase32ExperimentClaims(files, findings, allAdded, names)

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
  // Dedupe identical messages
  const seen = new Set()
  const deduped = findings.filter((f) => {
    const k = `${f.severity}|${f.file}|${f.message}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  const blockers2 = deduped.filter((f) => f.severity === 'BLOCKER')
  const highs2 = deduped.filter((f) => f.severity === 'HIGH')

  let verdict = 'PASS'
  if (blockers2.length) verdict = 'BLOCK'
  else if (highs2.length) verdict = 'REQUEST_CHANGES'

  return {
    verdict,
    findings: deduped,
    summary: {
      files: names.length,
      blockers: blockers2.length,
      highs: highs2.length,
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

const thisFile = fileURLToPath(import.meta.url)
const invoked = process.argv[1] ? resolve(process.argv[1]) : ''
if (invoked && thisFile === invoked) {
  main()
}
