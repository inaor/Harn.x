#!/usr/bin/env node
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { createRuntime } from '../adapters/deepseek/index.js'
import { runAttackDemo } from '../demo/attack-demo.js'
import { renderReplay } from './replay.js'

function storeDir(flag?: string): string {
  return flag ?? join(homedir(), '.harnesssec', 'sessions')
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
    console.log('- unknown-mcp-tool-use  [ALERT]')
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
  attach dsh              Show how to install the DeepSeek adapter
  demo                    Run the Phase 1 attack-demo scenario
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
