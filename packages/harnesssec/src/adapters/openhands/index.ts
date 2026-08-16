/**
 * OpenHands adapter — maps PreToolUse / lifecycle HookEvents into Harn.x core.
 *
 * All vendor-specific naming lives here. Core rules stay unchanged.
 * Attach path: OpenHands HookConfig command → `harnesssec openhands-hook`.
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { FlightRecorder } from '../../core/recorder.js'
import { PolicyEngine } from '../../policy/engine.js'
import { defaultRules } from '../../policy/rules.js'
import { McpTrustRegistry, DEFAULT_MCP_TRUST } from '../../core/mcp-trust.js'
import {
  baseEvent,
  classifyToolSensitivity,
  extractShellCommand,
} from '../../events/helpers.js'
import type { HarnessEvent, TrustLevel } from '../../events/schema.js'
import { HARNESS_OPENHANDS, isMcpToolName, parseMcpToolName } from '../../events/schema.js'

export const HARNESS_NAME = HARNESS_OPENHANDS

/** OpenHands HookEvent JSON (stdin contract from HookExecutor). */
export interface OpenHandsHookEvent {
  event_type: string
  tool_name?: string | null
  tool_input?: Record<string, unknown> | null
  tool_response?: Record<string, unknown> | null
  message?: string | null
  session_id?: string | null
  working_dir?: string | null
  metadata?: Record<string, unknown>
}

export interface OpenHandsHookResult {
  decision: 'allow' | 'deny'
  reason?: string
  /** OpenHands exit code: 2 blocks, 0 allows. */
  exitCode: number
  sessionId: string
  events: HarnessEvent[]
}

interface SessionMeta {
  turn: number
  agentId: string
}

function metaPath(storeDir: string, sessionId: string): string {
  return join(storeDir, '.openhands-meta', `${sessionId}.json`)
}

function loadMeta(storeDir: string, sessionId: string): SessionMeta {
  const path = metaPath(storeDir, sessionId)
  if (!existsSync(path)) return { turn: 1, agentId: 'openhands-agent' }
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as SessionMeta
  } catch {
    return { turn: 1, agentId: 'openhands-agent' }
  }
}

function saveMeta(storeDir: string, sessionId: string, meta: SessionMeta): void {
  const dir = join(storeDir, '.openhands-meta')
  mkdirSync(dir, { recursive: true })
  writeFileSync(metaPath(storeDir, sessionId), JSON.stringify(meta, null, 2))
}

/**
 * Map OpenHands tool names onto Harn.x names so existing rules apply.
 * `terminal` → `bash` (shell semantics / credential rules).
 * MCP tools keep `mcp__server__tool` when already normalized; otherwise synthesize.
 */
export function mapOpenHandsToolName(toolName: string): string {
  const name = toolName.trim()
  if (!name) return name
  if (name === 'terminal' || name === 'TerminalTool' || name === 'bash') return 'bash'
  if (name === 'powershell' || name === 'pwsh') return 'pwsh'
  if (name === 'browser' || name.startsWith('browser_')) return 'web_fetch'
  if (isMcpToolName(name)) return name
  // OpenHands MCP may use server/tool forms — leave as-is for non-shell tools
  return name
}

export function extractOpenHandsCommand(toolInput: Record<string, unknown> | null | undefined): string | undefined {
  if (!toolInput) return undefined
  if (typeof toolInput.command === 'string') return toolInput.command
  return extractShellCommand(toolInput)
}

/** Detect untrusted context introductions from OpenHands prompt/message content. */
export function detectUntrustedMessage(message: string | null | undefined): boolean {
  if (!message) return false
  return /UNTRUSTED_CONTENT|HARNX_UNTRUSTED|<UNTRUSTED/i.test(message)
}

export function createOpenHandsRuntime(
  storeDir?: string,
  mcpTrust?: Record<string, TrustLevel>,
): { recorder: FlightRecorder; policy: PolicyEngine; storeDir: string } {
  const dir = storeDir ?? join(homedir(), '.harnesssec', 'sessions')
  mkdirSync(dir, { recursive: true })
  const recorder = new FlightRecorder(
    dir,
    new McpTrustRegistry({ ...DEFAULT_MCP_TRUST, ...mcpTrust }),
  )
  const policy = new PolicyEngine(recorder, defaultRules)
  return { recorder, policy, storeDir: dir }
}

function ensureSession(
  recorder: FlightRecorder,
  sessionId: string,
): void {
  if (recorder.getSession(sessionId)) return
  recorder.record(baseEvent({
    event_type: 'session.started',
    harness: { name: HARNESS_NAME },
    session: { id: sessionId },
    agent: { id: 'openhands-agent' },
    raw: { source_hook: 'openhands:SessionStart' },
  }))
}

/**
 * Developer/demo helper — seed same-turn untrusted context without OpenHands hooks.
 * NOT portability evidence. Live tests must use UserPromptSubmit instead.
 */
export function seedUntrustedContext(
  storeDir: string,
  sessionId: string,
  opts?: { turn?: number; source?: string; excerpt?: string },
): HarnessEvent {
  const { recorder } = createOpenHandsRuntime(storeDir)
  ensureSession(recorder, sessionId)
  const meta = loadMeta(storeDir, sessionId)
  const turn = opts?.turn ?? meta.turn
  meta.turn = turn
  saveMeta(storeDir, sessionId, meta)

  return recorder.record(baseEvent({
    event_type: 'context.introduced',
    harness: { name: HARNESS_NAME },
    session: { id: sessionId },
    turn,
    agent: { id: meta.agentId },
    context: {
      id: `ctx_oh_${turn}`,
      source_type: 'repository_file',
      source: opts?.source ?? 'untrusted-input',
      trust: 'untrusted',
      excerpt: opts?.excerpt ?? 'OpenHands untrusted context',
      turn,
    },
    raw: { source_hook: 'openhands:seed-untrusted-context' },
  }))
}

export function handleOpenHandsHook(
  event: OpenHandsHookEvent,
  storeDir?: string,
): OpenHandsHookResult {
  const { recorder, policy, storeDir: dir } = createOpenHandsRuntime(storeDir)
  const sessionId = String(event.session_id ?? 'openhands-unknown-session')
  const recorded: HarnessEvent[] = []
  const meta = loadMeta(dir, sessionId)
  ensureSession(recorder, sessionId)

  const type = event.event_type

  if (type === 'SessionStart') {
    const ev = recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      agent: { id: meta.agentId },
      raw: { source_hook: 'openhands:SessionStart' },
    }))
    recorded.push(ev)
    return { decision: 'allow', exitCode: 0, sessionId, events: recorded }
  }

  if (type === 'SessionEnd') {
    const ev = recorder.record(baseEvent({
      event_type: 'session.ended',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      agent: { id: meta.agentId },
      raw: { source_hook: 'openhands:SessionEnd' },
    }))
    recorded.push(ev)
    return { decision: 'allow', exitCode: 0, sessionId, events: recorded }
  }

  if (type === 'UserPromptSubmit') {
    const message = event.message ?? ''
    if (detectUntrustedMessage(message)) {
      const turn = meta.turn
      const ev = recorder.record(baseEvent({
        event_type: 'context.introduced',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn,
        agent: { id: meta.agentId },
        context: {
          id: `ctx_oh_msg_${Date.now().toString(36)}`,
          source_type: 'user_message',
          source: 'UserPromptSubmit',
          trust: 'untrusted',
          excerpt: message.slice(0, 240),
          turn,
        },
        raw: { source_hook: 'openhands:UserPromptSubmit' },
      }))
      recorded.push(ev)
    }
    // Advance turn after user message so subsequent tools associate with next turn
    // unless we want same-turn: for portability demo, keep same turn for immediate tools.
    // Policy uses same-turn association — do NOT advance here when untrusted was just introduced.
    saveMeta(dir, sessionId, meta)
    return { decision: 'allow', exitCode: 0, sessionId, events: recorded }
  }

  if (type === 'PreToolUse') {
    const ohName = event.tool_name ?? 'unknown'
    const mappedName = mapOpenHandsToolName(ohName)
    const toolInput = event.tool_input ?? {}
    const command = extractOpenHandsCommand(toolInput)
    const args: Record<string, unknown> = { ...toolInput }
    if (command && args.command === undefined) args.command = command

    const sensitivity = classifyToolSensitivity(mappedName, args)
    const turn = meta.turn
    const mcpMeta = isMcpToolName(mappedName) ? parseMcpToolName(mappedName) : undefined
    const mcpTrustLevel = mcpMeta ? recorder.mcpTrust.observe(mcpMeta.server) : undefined

    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn,
      agent: { id: meta.agentId },
      tool: {
        name: mappedName,
        call_id: typeof toolInput.call_id === 'string' ? toolInput.call_id : undefined,
        sensitivity,
        provider: mcpMeta ? 'mcp' : 'openhands',
      },
      ...mcpMeta ? {
        mcp: { server: mcpMeta.server, tool: mcpMeta.tool, trust: mcpTrustLevel! },
      } : {},
      action: {
        type: 'tool.request',
        target: mappedName,
        arguments: args,
      },
      capability: { used: mappedName },
      raw: {
        source_hook: 'openhands:PreToolUse',
        notes: `openhands_tool=${ohName}`,
      },
    }))
    recorded.push(requested)

    if (mappedName === 'bash' || mappedName === 'pwsh') {
      if (command) {
        recorded.push(recorder.record(baseEvent({
          event_type: 'shell.command_requested',
          harness: { name: HARNESS_NAME },
          session: { id: sessionId },
          turn,
          agent: { id: meta.agentId },
          tool: { name: mappedName, sensitivity },
          action: { type: 'shell.command', target: command, arguments: { command } },
          links: { parent_event: requested.id, tool_source: requested.id },
          raw: { source_hook: 'openhands:PreToolUse:terminal' },
        })))
      }
    }

    const verdict = policy.evaluateToolRequest(requested)
    recorded.push(verdict.event)

    if (verdict.decision === 'block') {
      recorded.push(recorder.record(baseEvent({
        event_type: 'tool.denied',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn,
        agent: { id: meta.agentId },
        tool: { name: mappedName, sensitivity },
        action: requested.action,
        policy: {
          decision: 'block',
          rule: verdict.rule?.id,
          severity: verdict.rule?.severity,
          reason: verdict.reason,
        },
        links: {
          result_of: requested.id,
          policy_decision_for: requested.id,
          ...requested.links?.candidate_context_source
            ? {
              candidate_context_source: requested.links.candidate_context_source,
              correlated_with: requested.links.candidate_context_source,
            }
            : {},
        },
        raw: { source_hook: 'openhands:PreToolUse:deny' },
      })))

      return {
        decision: 'deny',
        reason: verdict.reason ?? `Blocked by Harn.x (${verdict.rule?.id ?? 'policy'})`,
        exitCode: 2,
        sessionId,
        events: recorded,
      }
    }

    // alert → allow execution but recorded; OpenHands hooks don't have "alert" — allow.
    return {
      decision: 'allow',
      reason: verdict.reason,
      exitCode: 0,
      sessionId,
      events: recorded,
    }
  }

  if (type === 'PostToolUse') {
    const ohName = event.tool_name ?? 'unknown'
    const mappedName = mapOpenHandsToolName(ohName)
    const ev = recorder.record(baseEvent({
      event_type: 'tool.completed',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: meta.agentId },
      tool: { name: mappedName },
      action: {
        type: 'tool.result',
        target: mappedName,
        arguments: (event.tool_response ?? {}) as Record<string, unknown>,
      },
      raw: { source_hook: 'openhands:PostToolUse' },
    }))
    recorded.push(ev)
    return { decision: 'allow', exitCode: 0, sessionId, events: recorded }
  }

  // Stop / unknown — allow by default (fail-open at adapter boundary for non-PreToolUse)
  return { decision: 'allow', exitCode: 0, sessionId, events: recorded }
}
