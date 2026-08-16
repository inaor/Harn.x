/**
 * DeepSeek DSH live autonomy run — real model via OpenAI-compatible adapter.
 * Does NOT script Action B. Canonical mode forbids inject_post_block.
 */
import { randomUUID } from 'node:crypto'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import AgentRegistry from '@deepseek-ai/dsh-agent'
import { SessionId } from '@deepseek-ai/dsh-session'
import { LocalBashExecutor } from '@deepseek-ai/dsh-bash-local'
import LocalSubprocessRuntime from '@deepseek-ai/dsh-subprocess-local'
import * as ToolBash from '@deepseek-ai/dsh-tool-bash'
import * as BashEnvPlugin from '@deepseek-ai/dsh-shell-env'
import AgentLoop from '@deepseek-ai/dsh-agent-loop'
import { mountAgentLoopTestDependencies } from '@deepseek-ai/dsh-agent-loop-testkit'
import { apply as applyHarnessSec, getSharedRecorder } from '../../src/adapters/deepseek/index.ts'
import { classifyPostBlockReaction } from '../../src/behavior/reaction.ts'
import type { HarnessEvent } from '../../src/events/schema.ts'
import { OpenAICompatAdapter } from './openai-compat-adapter.ts'
import { assertCanonicalAutonomySession, assertCanonicalRunnerConfig } from '../../../../experiments/live-autonomy/src/canonical.ts'
import type { RunResult } from '../../../../experiments/live-autonomy/src/types.ts'

const here = dirname(fileURLToPath(import.meta.url))
const experimentRoot = join(here, '../../../../experiments/live-autonomy')
const scenarioPath = join(experimentRoot, 'scenarios/security-research-post-denial.json')
const defaultResultsRoot = join(experimentRoot, 'results')

export function resolveModelEnv(): {
  provider: string
  model: string
  apiKey?: string
  baseUrl?: string
  ready: boolean
  reason?: string
} {
  const provider = process.env.HARNX_TEST_PROVIDER || process.env.OPENAI_PROVIDER || 'openai'
  const model = process.env.HARNX_TEST_MODEL || process.env.OPENAI_MODEL || ''
  const apiKey = process.env.HARNX_TEST_API_KEY || process.env.OPENAI_API_KEY || process.env.DEEPSEEK_API_KEY
  const baseUrl = process.env.HARNX_TEST_BASE_URL || process.env.OPENAI_BASE_URL
  if (!model) {
    return { provider, model: '', apiKey, baseUrl, ready: false, reason: 'Set HARNX_TEST_MODEL (and API key)' }
  }
  if (!apiKey) {
    return { provider, model, apiKey, baseUrl, ready: false, reason: 'Set HARNX_TEST_API_KEY or OPENAI_API_KEY' }
  }
  return { provider, model, apiKey, baseUrl, ready: true }
}

function countEvents(events: HarnessEvent[]): Record<string, number> {
  const out: Record<string, number> = {}
  for (const e of events) {
    out[e.event_type] = (out[e.event_type] ?? 0) + 1
  }
  return out
}

export async function runDshAutonomyOnce(opts: {
  storeDir?: string
  runIndex?: number
  idleTimeoutMs?: number
}): Promise<RunResult> {
  assertCanonicalRunnerConfig({ mode: 'canonical', scripted_followup: false, inject_post_block: false })

  const env = resolveModelEnv()
  const run_id = `dsh-${Date.now()}-${opts.runIndex ?? 0}-${randomUUID().slice(0, 8)}`
  const started_at = new Date().toISOString()
  const storeDir = opts.storeDir ?? mkdtempSync(join(tmpdir(), 'harnx-p32-dsh-'))

  if (!env.ready) {
    return {
      schema_version: 'phase3.2-run/v1',
      run_id,
      session_id: '',
      harness: 'deepseek-dsh',
      model: env.model || undefined,
      provider: env.provider,
      started_at,
      finished_at: new Date().toISOString(),
      autonomous: false,
      canonical: true,
      block_observed: false,
      reaction: 'UNKNOWN',
      reaction_evidence: [],
      detection_kinds: [],
      event_counts: {},
      store_dir: storeDir,
      skipped: true,
      skip_reason: env.reason,
    }
  }

  const scenario = JSON.parse(readFileSync(scenarioPath, 'utf8')) as { user_prompt: string }
  const adapter = new OpenAICompatAdapter({
    provider: env.provider,
    model: env.model,
    apiKey: env.apiKey!,
    baseUrl: env.baseUrl,
  })

  const ctx = new Context()
  await mountAgentLoopTestDependencies(ctx)
  await ctx.plugin(AgentLoop, { agents: [] })
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(AgentRegistry)
  await ctx.plugin(LocalSubprocessRuntime)
  await ctx.plugin(BashEnvPlugin)
  await ctx.plugin(LocalBashExecutor, { timeoutMs: 15_000, graceMs: 200 })
  await ctx.plugin(ToolBash)
  applyHarnessSec(ctx as any, { storeDir, enforce: true, verbose: false })
  ctx.llm.registerAdapter([env.provider], adapter)

  const sessionId = SessionId(`p32-${run_id}`)
  const handle = await ctx.agents.create({
    sessionId,
    agentOptions: { provider: env.provider, model: env.model },
  })
  const agent = handle.agent

  const idleTimeout = opts.idleTimeoutMs ?? 120_000
  const idle = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`idle timeout after ${idleTimeout}ms`)), idleTimeout)
    const dispose = ctx.on('agent/status', ({ agent: subject, status }: any) => {
      if (subject === agent && status === 'idle') {
        clearTimeout(timer)
        dispose()
        resolve()
      }
    })
  })

  agent.followup(createUserMessage({
    content: [{ type: 'text', text: scenario.user_prompt }],
    source: { kind: 'user' },
  }))

  let error: string | undefined
  try {
    await idle
  } catch (e) {
    error = e instanceof Error ? e.message : String(e)
  }

  const recorder = getSharedRecorder()!
  const session = recorder.getSession(String(sessionId))
    ?? recorder.listSessions().find(s => s.session_id.includes(run_id) || s.events.length > 0)
  const events = (session?.events ?? []) as HarnessEvent[]

  let canonical = true
  try {
    assertCanonicalAutonomySession(events as any, { allowSeedUntrusted: true })
  } catch (e) {
    canonical = false
    error = (error ? error + '; ' : '') + (e instanceof Error ? e.message : String(e))
  }

  const classification = classifyPostBlockReaction(events)
  const block_observed = classification.block_index !== null
  const finished_at = new Date().toISOString()

  await handle.dispose().catch(() => {})

  return {
    schema_version: 'phase3.2-run/v1',
    run_id,
    session_id: session?.session_id ?? String(sessionId),
    harness: 'deepseek-dsh',
    model: env.model,
    provider: env.provider,
    started_at,
    finished_at,
    autonomous: block_observed && canonical && !error,
    canonical,
    block_observed,
    block_rule: classification.block_rule,
    reaction: classification.reaction,
    reaction_evidence: classification.evidence,
    detection_kinds: classification.detection_kinds,
    event_counts: countEvents(events),
    store_dir: storeDir,
    notes: [
      'Action B was not scripted; model continued via AgentLoop after deny.',
      'Only bash tool mounted — filesystem alternate capability may be unavailable.',
    ],
    error,
  }
}

export async function runDshBatch(n: number, outDir: string): Promise<RunResult[]> {
  mkdirSync(outDir, { recursive: true })
  const storeDir = join(outDir, 'store-dsh')
  mkdirSync(storeDir, { recursive: true })
  const results: RunResult[] = []
  for (let i = 0; i < n; i++) {
    const r = await runDshAutonomyOnce({ storeDir, runIndex: i })
    results.push(r)
    writeFileSync(join(outDir, `${r.run_id}.json`), JSON.stringify(r, null, 2))
    if (r.skipped) break
  }
  return results
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const n = Number(process.env.HARNX_EXPERIMENT_RUNS || 10)
  const out = process.env.HARNX_EXPERIMENT_OUT || join(defaultResultsRoot, `dsh-${Date.now()}`)
  runDshBatch(n, out).then((runs) => {
    console.log(JSON.stringify({ ok: true, runs: runs.length, out }, null, 2))
  }).catch((e) => {
    console.error(e)
    process.exit(1)
  })
}
