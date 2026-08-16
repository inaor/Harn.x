#!/usr/bin/env node
/**
 * Phase 3.2 live autonomy experiment runner.
 *
 * Usage:
 *   HARNX_TEST_MODEL=gpt-4o-mini OPENAI_API_KEY=... node --import tsx src/runner.ts --harness dsh --runs 10
 *   HARNX_TEST_MODEL=gpt-4o-mini OPENAI_API_KEY=... node --import tsx src/runner.ts --harness openhands --runs 10
 *   node --import tsx src/runner.ts --harness both --runs 10
 *
 * Without credentials, writes skipped results and exits 0 (infrastructure dry-run).
 */
import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { classifyPostBlockReaction } from '../../src/behavior/reaction.ts'
import type { HarnessEvent } from '../../src/events/schema.ts'
import { runDshBatch, resolveModelEnv } from './harness-dsh.ts'
import { aggregateRuns, type RunResult } from '../../../../experiments/live-autonomy/src/types.ts'
import { assertCanonicalRunnerConfig } from '../../../../experiments/live-autonomy/src/canonical.ts'

const here = dirname(fileURLToPath(import.meta.url))
const experimentRoot = join(here, '../../../../experiments/live-autonomy')
const ohPy = join(experimentRoot, 'src/harness-openhands.py')

function parseArgs(argv: string[]) {
  let harness = 'both'
  let runs = Number(process.env.HARNX_EXPERIMENT_RUNS || 10)
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--harness') harness = argv[++i] || harness
    if (argv[i] === '--runs') runs = Number(argv[++i] || runs)
  }
  return { harness, runs }
}

function reclassifyFromStore(run: RunResult): RunResult {
  if (!run.session_id || !run.store_dir) return run
  const path = join(run.store_dir, `${run.session_id}.json`)
  if (!existsSync(path)) return run
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8')) as { events?: HarnessEvent[] }
    const events = raw.events ?? []
    const c = classifyPostBlockReaction(events)
    return {
      ...run,
      reaction: c.reaction,
      reaction_evidence: c.evidence,
      detection_kinds: c.detection_kinds,
      block_observed: c.block_index !== null,
      block_rule: c.block_rule ?? run.block_rule,
    }
  } catch {
    return run
  }
}

function runOpenHandsBatch(n: number, outDir: string): RunResult[] {
  const env = {
    ...process.env,
    HARNX_EXPERIMENT_RUNS: String(n),
    HARNX_EXPERIMENT_OUT: outDir,
    OPENHANDS_SUPPRESS_BANNER: '1',
  }
  const repo = join(experimentRoot, '../..')
  const sdk = join(repo, 'openhands-sdk')
  const r = spawnSync('uv', ['run', 'python', ohPy], {
    cwd: existsSync(sdk) ? sdk : repo,
    env,
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024,
  })
  if (r.status === 2) {
    return [{
      schema_version: 'phase3.2-run/v1',
      run_id: `oh-skip-${Date.now()}`,
      session_id: '',
      harness: 'openhands',
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      autonomous: false,
      canonical: true,
      block_observed: false,
      reaction: 'UNKNOWN',
      reaction_evidence: [],
      detection_kinds: [],
      event_counts: {},
      store_dir: outDir,
      skipped: true,
      skip_reason: r.stdout || r.stderr || 'OpenHands SDK unavailable',
    }]
  }
  if (r.status !== 0) {
    throw new Error(`OpenHands runner failed: ${r.stderr || r.stdout}`)
  }
  const files = readdirSync(outDir).filter(f => f.startsWith('oh-') && f.endsWith('.json'))
  return files.map(f => JSON.parse(readFileSync(join(outDir, f), 'utf8')) as RunResult)
}

async function main() {
  assertCanonicalRunnerConfig({ mode: 'canonical' })
  const { harness, runs } = parseArgs(process.argv.slice(2))
  const stamp = Date.now()
  const outRoot = process.env.HARNX_EXPERIMENT_OUT || join(experimentRoot, 'results', `batch-${stamp}`)
  mkdirSync(outRoot, { recursive: true })

  const env = resolveModelEnv()
  console.error(JSON.stringify({
    phase: '3.2',
    harness,
    runs,
    model_ready: env.ready,
    model: env.model || null,
    provider: env.provider,
    reason: env.reason || null,
    out: outRoot,
  }))

  const all: RunResult[] = []

  if (harness === 'dsh' || harness === 'both') {
    const dshOut = join(outRoot, 'dsh')
    const dshRuns = await runDshBatch(runs, dshOut)
    all.push(...dshRuns.map(reclassifyFromStore))
    const agg = aggregateRuns(dshRuns.map(reclassifyFromStore))
    if (!env.ready) {
      agg.telemetry_gaps.push('No API credentials — DSH live autonomy skipped')
    }
    agg.telemetry_gaps.push('DSH experiment mounts bash only (no filesystem tool)')
    writeFileSync(join(dshOut, 'aggregate.json'), JSON.stringify(agg, null, 2))
  }

  if (harness === 'openhands' || harness === 'both') {
    const ohOut = join(outRoot, 'openhands')
    mkdirSync(ohOut, { recursive: true })
    const ohRuns = runOpenHandsBatch(runs, ohOut).map(reclassifyFromStore)
    all.push(...ohRuns)
    const agg = aggregateRuns(ohRuns)
    if (!env.ready) {
      agg.telemetry_gaps.push('No API credentials — OpenHands live autonomy skipped')
    }
    agg.telemetry_gaps.push('OpenHands live subagent.* lineage remains PARTIAL')
    writeFileSync(join(ohOut, 'aggregate.json'), JSON.stringify(agg, null, 2))
  }

  writeFileSync(join(outRoot, 'summary.json'), JSON.stringify({
    schema_version: 'phase3.2-summary/v1',
    generated_at: new Date().toISOString(),
    model_ready: env.ready,
    runs: all,
  }, null, 2))

  console.log(JSON.stringify({
    ok: true,
    out: outRoot,
    total_runs: all.length,
    skipped: all.filter(r => r.skipped).length,
    autonomous: all.filter(r => r.autonomous).length,
  }, null, 2))
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
