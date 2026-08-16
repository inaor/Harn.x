/**
 * OpenHands PreToolUse / lifecycle hook entry.
 * Reads HookEvent JSON from stdin; prints decision JSON; exit 2 = deny.
 */
import { handleOpenHandsHook, type OpenHandsHookEvent } from './index.js'

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer)
  return Buffer.concat(chunks).toString('utf8')
}

async function main(): Promise<void> {
  const storeDir = process.env.HARNX_STORE ?? process.env.HARNESSSEC_STORE
  const raw = await readStdin()
  let event: OpenHandsHookEvent
  try {
    event = JSON.parse(raw) as OpenHandsHookEvent
  } catch (err) {
    // Fail closed: OpenHands only blocks on exit 2 (exit 1 is non-blocking).
    console.error(`harnx openhands-hook: invalid JSON: ${err}`)
    process.stdout.write(`${JSON.stringify({
      decision: 'deny',
      reason: 'Harn.x hook received invalid HookEvent JSON',
    })}\n`)
    process.exit(2)
  }

  try {
    const result = handleOpenHandsHook(event, storeDir)
    const payload: Record<string, unknown> = {
      decision: result.decision,
    }
    if (result.reason) payload.reason = result.reason
    process.stdout.write(`${JSON.stringify(payload)}\n`)
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

main().catch((err) => {
  console.error(err)
  process.stdout.write(`${JSON.stringify({
    decision: 'deny',
    reason: 'Harn.x hook fatal error',
  })}\n`)
  process.exit(2)
})
