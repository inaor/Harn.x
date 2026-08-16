/**
 * Cursor Agent hook entry — stdin JSON → Harn.x → stdout JSON.
 * Exit 2 ≡ deny (Cursor + Claude Code compatible).
 * Prefer permission:"deny" in JSON; failClosed should be set in hooks.json.
 */
import { handleCursorHook, type CursorHookEvent } from './index.js'

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer)
  return Buffer.concat(chunks).toString('utf8')
}

async function main(): Promise<void> {
  const storeDir = process.env.HARNX_STORE ?? process.env.HARNESSSEC_STORE
  const raw = await readStdin()
  let event: CursorHookEvent
  try {
    event = JSON.parse(raw) as CursorHookEvent
  } catch (err) {
    console.error(`harnx cursor-hook: invalid JSON: ${err}`)
    // Deny closed for gate hooks when JSON is corrupt
    process.stdout.write(`${JSON.stringify({
      permission: 'deny',
      user_message: 'Harn.x hook received invalid Cursor hook JSON',
      agent_message: 'Harn.x hook received invalid Cursor hook JSON',
    })}\n`)
    process.exit(2)
  }

  try {
    const result = handleCursorHook(event, storeDir)
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

main().catch((err) => {
  console.error(err)
  process.stdout.write(`${JSON.stringify({
    permission: 'deny',
    user_message: 'Harn.x cursor-hook fatal error',
    agent_message: 'Harn.x cursor-hook fatal error',
  })}\n`)
  process.exit(2)
})
