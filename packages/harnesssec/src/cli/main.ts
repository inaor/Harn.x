#!/usr/bin/env node
import { mkdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { createRuntime } from '../adapters/deepseek/index.js'
import { runAttackDemo } from '../demo/attack-demo.js'
import { renderIncident } from '../behavior/render.js'
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
    if (target === 'cursor') {
      console.log('Cursor install (official hooks — no Marketplace invent):')
      console.log('  1. Prefer project hooks in a trusted workspace:')
      console.log('       .cursor/hooks.json  +  .cursor/hooks/harnx-cursor.sh')
      console.log('  2. Or user hooks: ~/.cursor/hooks.json (commands relative to ~/.cursor/)')
      console.log('  3. Wire deny-capable hooks with failClosed:true to:')
      console.log('       HARNX_STORE=<dir> harnesssec cursor-hook')
      console.log('     (stdin = Cursor hook JSON; exit 2 / permission:deny = block)')
      console.log('  Canonical enforcement: beforeShellExecution only.')
      console.log('  See docs/cursor-architecture.md and experiments/cursor-lab/')
      console.log('')
      console.log(`Flight records write to: ${dir}`)
      return
    }
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

  if (cmd === 'cursor-hook') {
    const { handleCursorHook } = await import('../adapters/cursor/index.js')
    const { resolveCursorHookRules } = await import('./cursor-lab-policy.js')
    const chunks: Buffer[] = []
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer)
    const raw = Buffer.concat(chunks).toString('utf8')
    let event: import('../adapters/cursor/index.js').CursorHookEvent
    try {
      event = JSON.parse(raw)
    } catch (err) {
      console.error(`invalid Cursor hook JSON: ${err}`)
      process.stdout.write(`${JSON.stringify({
        permission: 'deny',
        user_message: 'Harn.x hook received invalid Cursor hook JSON',
        agent_message: 'Harn.x hook received invalid Cursor hook JSON',
      })}\n`)
      process.exit(2)
    }
    try {
      // Lab env (HARNX_LAB_POLICY) is interpreted only at this CLI boundary.
      const result = handleCursorHook(event, dir, resolveCursorHookRules())
      process.stdout.write(`${JSON.stringify(result.response)}\n`)
      process.exit(result.blocked ? 2 : 0)
    } catch (err) {
      console.error(err)
      process.stdout.write(`${JSON.stringify({
        permission: 'deny',
        user_message: `Harn.x hook internal error: ${err instanceof Error ? err.message : String(err)}`,
        agent_message: `Harn.x hook internal error: ${err instanceof Error ? err.message : String(err)}`,
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
    if (process.env.HARNX_LAB_POLICY === 'phase4a') {
      console.log('')
      console.log('Note: HARNX_LAB_POLICY=phase4a is set. It affects only cursor-hook')
      console.log('(explicit injection of experimental phase4a lab rules), not defaultRules')
      console.log('or DeepSeek/OpenHands adapters.')
    }
    return
  }

  if (cmd === 'detections') {
    const id = rest[0]
    const sessions = id ? [recorder.getSession(id)].filter(Boolean) : recorder.listSessions()
    for (const s of sessions) {
      if (!s) continue
      const policyDets = s.events.filter((e: { event_type: string; policy?: { decision?: string } }) =>
        e.event_type === 'policy.decision' && e.policy?.decision !== 'allow',
      )
      const behaviorDets = s.events.filter((e: { event_type: string }) => e.event_type === 'behavior.detection')
      console.log(`# ${s.session_id}`)
      console.log('## policy')
      for (const d of policyDets) {
        console.log(`${d.timestamp}  ${d.policy?.decision?.toUpperCase()}  ${d.policy?.rule}  ${d.policy?.reason}`)
      }
      if (!policyDets.length) console.log('(none)')
      console.log('## behavior')
      for (const d of behaviorDets) {
        console.log(`${d.timestamp}  ${d.detection?.severity?.toUpperCase()}  ${d.detection?.kind}  ${d.detection?.title}`)
      }
      if (!behaviorDets.length) console.log('(none)')
      console.log('')
    }
    return
  }

  if (cmd === 'why') {
    const id = rest[0]
    if (!id) {
      console.error('usage: harnesssec why <session-id|event-id>')
      process.exit(1)
    }
    const sessions = recorder.listSessions()
    const session = recorder.getSession(id)
      ?? sessions.find(s => s.events.some(e => e.id === id))
    if (!session) {
      console.error(`session/event not found: ${id}`)
      process.exit(1)
    }
    const denied = session.events.filter(e => e.event_type === 'tool.denied')
    const decisions = session.events.filter(e =>
      e.event_type === 'policy.decision' && e.policy?.decision === 'block',
    )
    const contexts = session.events.filter(e =>
      e.event_type === 'context.introduced' && e.context?.trust === 'untrusted',
    )
    const focus = session.events.find(e => e.id === id)
      ?? denied[denied.length - 1]
      ?? decisions[decisions.length - 1]

    console.log('HARN.X WHY')
    console.log('')
    console.log('Session:', session.session_id)
    console.log('Harness:', focus?.harness?.name ?? session.events[0]?.harness?.name ?? '-')
    console.log('')
    console.log('Previous context:')
    if (!contexts.length) console.log('(none recorded)')
    for (const c of contexts.slice(-3)) {
      console.log(`- ${c.context?.source_type}/${c.context?.source} trust=${c.context?.trust}`)
      if (c.context?.excerpt) console.log(`  excerpt: ${c.context.excerpt.slice(0, 160)}`)
    }
    console.log('')
    console.log('Requested action:')
    console.log(focus?.action?.type ?? focus?.event_type ?? '-')
    console.log('')
    console.log('Target:')
    console.log(focus?.action?.target ?? focus?.tool?.name ?? '-')
    console.log('')
    console.log('Policy evidence:')
    for (const d of decisions.slice(-5)) {
      console.log(`- ${d.policy?.rule}: ${d.policy?.reason}`)
    }
    if (!decisions.length) console.log('(no block decisions)')
    console.log('')
    console.log('Decision:')
    console.log(focus?.policy?.decision?.toUpperCase()
      ?? (denied.length ? 'BLOCK' : 'ALLOW/NONE'))
    console.log('')
    console.log('No LLM inference was used.')
    return
  }

  if (cmd === 'status') {
    let harness = 'all'
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '--harness') harness = rest[++i] ?? harness
    }
    const sessions = recorder.listSessions()
    const recent = sessions
      .filter(s => harness === 'all' || s.events.some(e => e.harness?.name === harness
        || (harness === 'cursor' && e.harness?.name === 'cursor')))
      .slice(-5)
    const cursorSessions = sessions.filter(s => s.events.some(e => e.harness?.name === 'cursor'))
    const active = harness === 'cursor'
      ? cursorSessions.length > 0
      : sessions.length > 0

    console.log('HARN.X')
    console.log('')
    console.log('Harness       ', harness === 'cursor' ? 'Cursor' : harness)
    console.log('Connection    ', active ? 'ACTIVE' : 'INACTIVE')
    console.log('Policy        ', 'Default')
    console.log('Recording     ', 'ON')
    console.log('Behavior      ', 'ON')
    console.log('')
    console.log('Protection:')
    if (harness === 'cursor' || harness === 'all') {
      console.log('Shell          ✓   (beforeShellExecution deny; failClosed required in hooks.json)')
      console.log('Files          PARTIAL   (beforeReadFile; no full content persist; policy rarely blocks Read alone)')
      console.log('MCP            PARTIAL')
      console.log('Lineage        PARTIAL / unavailable   (subagent observation-only; no agent UUID)')
    } else {
      console.log('(use --harness cursor for Cursor capability matrix)')
    }
    console.log('')
    console.log(`Store: ${dir}`)
    console.log(`Recent sessions: ${recent.length ? recent.map(s => s.session_id).join(', ') : '(none)'}`)
    return
  }

  if (cmd === 'incident') {
    const id = rest[0]
    if (!id) {
      console.error('usage: harnesssec incident <session-id>')
      process.exit(1)
    }
    console.log(renderIncident(recorder, id))
    return
  }

  console.error(`unknown command: ${cmd}`)
  printHelp()
  process.exit(1)
}

function printHelp(): void {
  console.log(`harnesssec — harness-native flight recorder

Commands:
  attach dsh|openhands|cursor  Show how to install an adapter
  demo                         Run the Phase 1 attack-demo scenario
  cursor-hook                  Cursor Agent stdin hook (permission:deny / exit 2)
  openhands-hook               OpenHands PreToolUse stdin hook (exit 2 = deny)
  openhands-seed               Seed untrusted context for an OpenHands session
  sessions                     List recorded sessions
  inspect <session>            Inspect a session
  replay <session>             Forensic replay of a session
  why <session|event>          Explain last block (no LLM)
  status [--harness cursor]    Honest connection/capability status
  graph <session>              Print causal event graph
  agents [session]             Show agent lineage
  policies                     List active rules
  detections [session]         List non-allow policy decisions and behavioral detections
  incident <session>           Render HARN.X INCIDENT behavioral timeline

Options:
  --store <dir>           Session store directory (default: ~/.harnesssec/sessions)
`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
