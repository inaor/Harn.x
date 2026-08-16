#!/usr/bin/env node
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { createRuntime } from '../adapters/deepseek/index.js'
import { runAttackDemo } from '../demo/attack-demo.js'
import { renderReplay } from './replay.js'

function storeDir(flag?: string): string {
  return flag
    ?? process.env.HARNX_STORE
    ?? process.env.HARNESSSEC_STORE
    ?? join(homedir(), '.harnesssec', 'sessions')
}

/** Strip `--store <dir>` (and other flags later) so `cmd` is the real subcommand. */
function parseArgs(argv: string[]): { cmd?: string; rest: string[]; store?: string } {
  const rest: string[] = []
  let store: string | undefined
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--store') {
      store = argv[++i]
      continue
    }
    if (a === '--help' || a === '-h') {
      rest.push('help')
      continue
    }
    rest.push(a)
  }
  return { cmd: rest[0], rest: rest.slice(1), store }
}

async function main(): Promise<void> {
  const { cmd, rest, store } = parseArgs(process.argv.slice(2))
  const dir = storeDir(store)

  if (!cmd || cmd === 'help') {
    printHelp()
    return
  }

  if (cmd === 'attach') {
    const target = rest[0] ?? 'dsh'
    console.log(`HarnessSec attach target: ${target}`)
    console.log('')
    if (target === 'openhands' || target === 'oh') {
      console.log('OpenHands install (no fork) — PreToolUse hook:')
      console.log('  Configure HookConfig / .openhands/hooks.json to run:')
      console.log('    HARNX_STORE=<dir> node <path>/dist/adapters/openhands/hook-cli.js')
      console.log('  or:  harnesssec openhands-hook   (stdin = HookEvent JSON)')
      console.log('')
      console.log('Seed untrusted context for demos (NOT portability evidence):')
      console.log('  harnesssec openhands-seed --session <id> --store <dir>')
      console.log('  Live portability tests must use UserPromptSubmit instead.')
      console.log('')
      console.log(`Flight records write to: ${dir}`)
      return
    }
    console.log('DeepSeek Harness install (no fork):')
    console.log('  dsh plugin --profile web add <path-to-packages/harnesssec>')
    console.log('')
    console.log('The Cordis plugin entry is:')
    console.log('  harnesssec/adapters/deepseek  (export apply / name / inject)')
    console.log('')
    console.log(`Flight records write to: ${dir}`)
    console.log('Then use: harnesssec sessions | replay <id> | graph <id>')
    return
  }

  if (cmd === 'openhands-hook') {
    const { handleOpenHandsHook } = await import('../adapters/openhands/index.js')
    const chunks: Buffer[] = []
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer)
    const raw = Buffer.concat(chunks).toString('utf8')
    let event: import('../adapters/openhands/index.js').OpenHandsHookEvent
    try {
      event = JSON.parse(raw)
    } catch (err) {
      console.error(`invalid HookEvent JSON: ${err}`)
      process.stdout.write(`${JSON.stringify({
        decision: 'deny',
        reason: 'Harn.x hook received invalid HookEvent JSON',
      })}\n`)
      process.exit(2)
    }
    try {
      const result = handleOpenHandsHook(event, dir)
      process.stdout.write(`${JSON.stringify({
        decision: result.decision,
        ...result.reason ? { reason: result.reason } : {},
      })}\n`)
      process.exit(result.exitCode)
    } catch (err) {
      console.error(err)
      process.stdout.write(`${JSON.stringify({
        decision: 'deny',
        reason: `Harn.x hook internal error: ${err instanceof Error ? err.message : String(err)}`,
      })}\n`)
      process.exit(2)
    }
  }

  if (cmd === 'openhands-seed') {
    const { seedUntrustedContext } = await import('../adapters/openhands/index.js')
    let sessionId = 'openhands-live'
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '--session') sessionId = rest[++i] ?? sessionId
    }
    const ev = seedUntrustedContext(dir, sessionId)
    console.log(`seeded untrusted context session=${sessionId} event=${ev.id} turn=${ev.turn}`)
    return
  }

  if (cmd === 'demo') {
    mkdirSync(dir, { recursive: true })
    // Replace prior attack-demo artifact so replay is deterministic.
    rmSync(join(dir, 'attack-demo.json'), { force: true })
    const result = runAttackDemo(dir)
    console.log(result.summary)
    console.log('')
    console.log(renderReplay(result.recorder, result.sessionId))
    console.log('')
    console.log(`Stored: ${join(dir, `${result.sessionId}.json`)}`)
    return
  }

  const { recorder } = createRuntime(dir)

  if (cmd === 'sessions') {
    const sessions = recorder.listSessions()
    if (!sessions.length) {
      console.log('(no sessions — run `harnesssec demo` or attach to dsh)')
      return
    }
    for (const s of sessions) {
      console.log(`${s.session_id}  started=${s.started_at}  events=${s.events.length}  objective=${s.objective?.description ?? '-'}`)
    }
    return
  }

  if (cmd === 'inspect' || cmd === 'replay') {
    const id = rest[0]
    if (!id) {
      console.error(`usage: harnesssec ${cmd} <session-id>`)
      process.exit(1)
    }
    console.log(renderReplay(recorder, id))
    return
  }

  if (cmd === 'graph') {
    const id = rest[0]
    if (!id) {
      console.error('usage: harnesssec graph <session-id>')
      process.exit(1)
    }
    console.log(recorder.graph.render(id))
    return
  }

  if (cmd === 'agents') {
    const id = rest[0]
    if (!id) {
      for (const s of recorder.listSessions()) {
        console.log(`# ${s.session_id}`)
        console.log(recorder.lineage.tree(s.session_id))
        console.log('')
      }
      return
    }
    console.log(recorder.lineage.tree(id))
    return
  }

  if (cmd === 'policies') {
    console.log(`Rules loaded from defaultRules (store=${dir})`)
    console.log('- credential-path-in-shell-args  [BLOCK]')
    console.log('- untrusted-context-sensitive-tool  [BLOCK]')
    console.log('- untrusted-mcp-tool-use  [ALERT] (explicit untrusted only)')
    return
  }

  if (cmd === 'detections') {
    const id = rest[0]
    const sessions = id ? [recorder.getSession(id)].filter(Boolean) : recorder.listSessions()
    for (const s of sessions) {
      if (!s) continue
      const dets = s.events.filter((e: { event_type: string; policy?: { decision?: string } }) =>
        e.event_type === 'policy.decision' && e.policy?.decision !== 'allow',
      )
      console.log(`# ${s.session_id}`)
      for (const d of dets) {
        console.log(`${d.timestamp}  ${d.policy?.decision?.toUpperCase()}  ${d.policy?.rule}  ${d.policy?.reason}`)
      }
      if (!dets.length) console.log('(none)')
      console.log('')
    }
    return
  }

  console.error(`unknown command: ${cmd}`)
  printHelp()
  process.exit(1)
}

function printHelp(): void {
  console.log(`harnesssec — harness-native flight recorder

Commands:
  attach dsh|openhands    Show how to install an adapter
  demo                    Run the Phase 1 attack-demo scenario
  openhands-hook          OpenHands PreToolUse stdin hook (exit 2 = deny)
  openhands-seed          Seed untrusted context for an OpenHands session
  sessions                List recorded sessions
  inspect <session>       Inspect a session
  replay <session>        Forensic replay of a session
  graph <session>         Print causal event graph
  agents [session]        Show agent lineage
  policies                List active rules
  detections [session]    List non-allow policy decisions

Options:
  --store <dir>           Session store directory (default: ~/.harnesssec/sessions)
`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
