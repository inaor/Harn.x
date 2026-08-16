/**
 * Cursor adapter — maps official Cursor Agent hooks → Harn.x core.
 *
 * Vendor-specific naming stays here. No model-provider credentials.
 * Canonical enforcement proof: beforeShellExecution + deny + failClosed.
 * subagentStart is observation-only (no block claim from response alone).
 * beforeReadFile: never persist full file contents by default.
 */

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { FlightRecorder } from '../../core/recorder.js'
import { PolicyEngine } from '../../policy/engine.js'
import type { PolicyRule } from '../../policy/engine.js'
import { defaultRules } from '../../policy/rules.js'
import { McpTrustRegistry, DEFAULT_MCP_TRUST } from '../../core/mcp-trust.js'
import {
  baseEvent,
  classifyToolSensitivity,
  extractShellCommand,
} from '../../events/helpers.js'
import type { HarnessEvent, TrustLevel } from '../../events/schema.js'
import { HARNESS_CURSOR, isMcpToolName, parseMcpToolName } from '../../events/schema.js'

export const HARNESS_NAME = HARNESS_CURSOR

/** Cursor hook stdin JSON (official hooks schema; fields vary by event). */
export interface CursorHookEvent {
  hook_event_name?: string
  conversation_id?: string
  generation_id?: string
  session_id?: string
  model?: string
  model_id?: string
  cursor_version?: string
  workspace_roots?: string[]
  transcript_path?: string | null
  user_email?: string | null
  // shell
  command?: string
  cwd?: string
  // tools
  tool_name?: string
  tool_input?: Record<string, unknown> | string
  tool_use_id?: string
  // read
  file_path?: string
  content?: string
  attachments?: Array<{ type?: string; file_path?: string }>
  // prompt
  prompt?: string
  // mcp
  tool?: string
  // subagent
  subagent_id?: string
  subagent_type?: string
  parent_conversation_id?: string
  // post / stop
  status?: string
  text?: string
  [key: string]: unknown
}

export interface CursorHookResult {
  /** Cursor-native stdout JSON fields */
  response: Record<string, unknown>
  sessionId: string
  events: HarnessEvent[]
  blocked: boolean
  blockFeedback?: string
}

interface SessionMeta {
  turn: number
  agentId: string
}

function metaPath(storeDir: string, sessionId: string): string {
  return join(storeDir, '.cursor-meta', `${sessionId}.json`)
}

function loadMeta(storeDir: string, sessionId: string): SessionMeta {
  const path = metaPath(storeDir, sessionId)
  if (!existsSync(path)) return { turn: 1, agentId: 'cursor-agent' }
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as SessionMeta
  } catch {
    return { turn: 1, agentId: 'cursor-agent' }
  }
}

function saveMeta(storeDir: string, sessionId: string, meta: SessionMeta): void {
  const dir = join(storeDir, '.cursor-meta')
  mkdirSync(dir, { recursive: true })
  writeFileSync(metaPath(storeDir, sessionId), JSON.stringify(meta, null, 2))
}

export function createCursorRuntime(
  storeDir?: string,
  mcpTrust?: Record<string, TrustLevel>,
  rules: PolicyRule[] = defaultRules,
): { recorder: FlightRecorder; policy: PolicyEngine; storeDir: string } {
  const dir = storeDir ?? join(homedir(), '.harnesssec', 'sessions')
  mkdirSync(dir, { recursive: true })
  const recorder = new FlightRecorder(
    dir,
    new McpTrustRegistry({ ...DEFAULT_MCP_TRUST, ...mcpTrust }),
  )
  const policy = new PolicyEngine(recorder, rules)
  return { recorder, policy, storeDir: dir }
}

function sessionIdOf(event: CursorHookEvent): string {
  return String(
    event.conversation_id
    ?? event.session_id
    ?? event.parent_conversation_id
    ?? 'cursor-unknown-session',
  )
}

function hookName(event: CursorHookEvent): string {
  return String(event.hook_event_name ?? 'unknown')
}

function parseToolInput(raw: CursorHookEvent['tool_input']): Record<string, unknown> {
  if (!raw) return {}
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw) as unknown
      return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : { raw }
    } catch {
      return { raw }
    }
  }
  return { ...raw }
}

/** Map Cursor tool names onto Harn.x names so existing rules apply. */
export function mapCursorToolName(toolName: string): string {
  const n = toolName.trim()
  if (!n) return n
  if (n === 'Shell' || n === 'shell' || n === 'Bash' || n === 'bash') return 'bash'
  if (n === 'Read' || n === 'read') return 'read'
  if (n === 'Write' || n === 'write' || n === 'Edit') return 'write'
  if (n === 'Delete') return 'delete'
  if (n === 'Task') return 'Task'
  if (n.startsWith('MCP:') || n.startsWith('mcp__')) {
    if (isMcpToolName(n)) return n
    const rest = n.replace(/^MCP:/i, '')
    const [server, ...toolParts] = rest.split('/')
    if (server && toolParts.length) return `mcp__${server}__${toolParts.join('__')}`
    return n
  }
  return n
}

export function detectUntrustedText(text: string | null | undefined): boolean {
  if (!text) return false
  return /UNTRUSTED_CONTENT|HARNX_UNTRUSTED|<UNTRUSTED/i.test(text)
}

function contentHash(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex')
}

/**
 * Developer-facing block banner (WHO / WHAT / WHY / RESULT).
 * Kept adapter-local — not a dashboard.
 */
export function formatBlockFeedback(opts: {
  action: string
  target: string
  policyRule?: string
  reason?: string
}): string {
  return [
    'HARN.X BLOCKED',
    '',
    'Agent:',
    'Cursor',
    '',
    'Action:',
    opts.action,
    '',
    'Target:',
    opts.target,
    '',
    'Policy:',
    opts.policyRule ?? 'policy',
    '',
    'Execution:',
    'Prevented',
    opts.reason ? `\nDetail:\n${opts.reason}` : '',
  ].filter((line, i, arr) => !(line === '' && arr[i - 1] === '')).join('\n').trim()
}

function ensureSession(recorder: FlightRecorder, sessionId: string, meta: SessionMeta): void {
  if (recorder.getSession(sessionId)) return
  recorder.record(baseEvent({
    event_type: 'session.started',
    harness: { name: HARNESS_NAME },
    session: { id: sessionId },
    agent: { id: meta.agentId },
    raw: { source_hook: 'cursor:ensure-session' },
  }))
}

function allow(sessionId: string, events: HarnessEvent[], extra?: Record<string, unknown>): CursorHookResult {
  return {
    response: { permission: 'allow', ...extra },
    sessionId,
    events,
    blocked: false,
  }
}

function deny(
  sessionId: string,
  events: HarnessEvent[],
  feedback: string,
  extra?: Record<string, unknown>,
): CursorHookResult {
  return {
    response: {
      permission: 'deny',
      user_message: feedback,
      agent_message: feedback,
      ...extra,
    },
    sessionId,
    events,
    blocked: true,
    blockFeedback: feedback,
  }
}

/**
 * Handle one Cursor hook invocation.
 * Enforcement decisions are only returned for hooks that Cursor documents as
 * gateable. subagentStart always observes and allows.
 */
export function handleCursorHook(
  event: CursorHookEvent,
  storeDir?: string,
  rules: PolicyRule[] = defaultRules,
): CursorHookResult {
  const { recorder, policy, storeDir: dir } = createCursorRuntime(storeDir, undefined, rules)
  const sessionId = sessionIdOf(event)
  const recorded: HarnessEvent[] = []
  const meta = loadMeta(dir, sessionId)
  const name = hookName(event)
  ensureSession(recorder, sessionId, meta)

  const modelMeta = {
    model: event.model,
    model_id: event.model_id,
    cursor_version: event.cursor_version,
  }

  if (name === 'sessionStart') {
    const ev = recorder.record(baseEvent({
      event_type: 'session.started',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      agent: { id: meta.agentId },
      raw: { source_hook: 'cursor:sessionStart', ...modelMeta },
    }))
    recorded.push(ev)
    saveMeta(dir, sessionId, meta)
    // Fire-and-forget per docs — empty / allow-shaped response
    return { response: {}, sessionId, events: recorded, blocked: false }
  }

  if (name === 'sessionEnd') {
    recorded.push(recorder.record(baseEvent({
      event_type: 'session.ended',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      agent: { id: meta.agentId },
      raw: { source_hook: 'cursor:sessionEnd' },
    })))
    return { response: {}, sessionId, events: recorded, blocked: false }
  }

  if (name === 'beforeSubmitPrompt') {
    const prompt = String(event.prompt ?? '')
    if (detectUntrustedText(prompt)) {
      recorded.push(recorder.record(baseEvent({
        event_type: 'context.introduced',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn: meta.turn,
        agent: { id: meta.agentId },
        context: {
          id: `ctx_cursor_${Date.now().toString(36)}`,
          source_type: 'user_message',
          source: 'beforeSubmitPrompt',
          trust: 'untrusted',
          excerpt: prompt.slice(0, 240),
          turn: meta.turn,
        },
        raw: { source_hook: 'cursor:beforeSubmitPrompt' },
      })))
    }
    saveMeta(dir, sessionId, meta)
    return {
      response: { continue: true },
      sessionId,
      events: recorded,
      blocked: false,
    }
  }

  // --- Canonical enforcement: beforeShellExecution ---
  if (name === 'beforeShellExecution') {
    const command = String(event.command ?? extractShellCommand(event) ?? '')
    const args: Record<string, unknown> = { command }
    if (event.cwd) args.cwd = event.cwd
    const mappedName = 'bash'
    const sensitivity = classifyToolSensitivity(mappedName, args)
    const turn = meta.turn

    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn,
      agent: { id: meta.agentId },
      tool: { name: mappedName, sensitivity, provider: 'cursor' },
      action: { type: 'tool.request', target: mappedName, arguments: args },
      capability: { used: mappedName },
      raw: { source_hook: 'cursor:beforeShellExecution', ...modelMeta },
    }))
    recorded.push(requested)

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
        raw: { source_hook: 'cursor:beforeShellExecution:shell' },
      })))
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
        },
        raw: { source_hook: 'cursor:beforeShellExecution:deny' },
      })))

      const actionLabel = /(?:\.ssh|\.aws|id_rsa|id_ed25519|credentials|\.env)/i.test(command)
        ? 'READ_SENSITIVE_FILE'
        : 'EXECUTE_COMMAND'
      const fb = formatBlockFeedback({
        action: actionLabel,
        target: command.slice(0, 200),
        policyRule: verdict.rule?.id,
        reason: verdict.reason,
      })
      return deny(sessionId, recorded, fb)
    }

    return allow(sessionId, recorded)
  }

  if (name === 'afterShellExecution') {
    const command = String(event.command ?? '')
    recorded.push(recorder.record(baseEvent({
      event_type: 'tool.completed',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: meta.agentId },
      tool: { name: 'bash' },
      action: {
        type: 'tool.result',
        target: 'bash',
        arguments: { command: command.slice(0, 500) },
      },
      raw: { source_hook: 'cursor:afterShellExecution' },
    })))
    return { response: {}, sessionId, events: recorded, blocked: false }
  }

  if (name === 'beforeReadFile') {
    const filePath = String(event.file_path ?? '')
    const content = typeof event.content === 'string' ? event.content : ''
    const hash = content ? contentHash(content) : undefined
    // Detect untrusted markers without persisting full content
    if (detectUntrustedText(content)) {
      recorded.push(recorder.record(baseEvent({
        event_type: 'context.introduced',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn: meta.turn,
        agent: { id: meta.agentId },
        context: {
          id: `ctx_cursor_file_${Date.now().toString(36)}`,
          source_type: 'repository_file',
          source: filePath || 'beforeReadFile',
          trust: 'untrusted',
          excerpt: content.slice(0, 120),
          turn: meta.turn,
        },
        raw: {
          source_hook: 'cursor:beforeReadFile:untrusted',
          notes: hash ? `sha256=${hash}` : undefined,
        },
      })))
    }

    const args: Record<string, unknown> = { path: filePath }
    if (hash) args.content_sha256 = hash
    // Intentionally omit full content from persisted action.arguments
    const mappedName = 'read'
    const sensitivity = classifyToolSensitivity(mappedName, args)
    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: meta.agentId },
      tool: { name: mappedName, sensitivity, provider: 'cursor' },
      action: { type: 'tool.request', target: mappedName, arguments: args },
      capability: { used: mappedName },
      raw: {
        source_hook: 'cursor:beforeReadFile',
        notes: hash ? `sha256=${hash}; content_persisted=false` : 'content_persisted=false',
      },
    }))
    recorded.push(requested)

    const verdict = policy.evaluateToolRequest(requested)
    recorded.push(verdict.event)

    if (verdict.decision === 'block') {
      recorded.push(recorder.record(baseEvent({
        event_type: 'tool.denied',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn: meta.turn,
        agent: { id: meta.agentId },
        tool: { name: mappedName, sensitivity },
        action: requested.action,
        policy: {
          decision: 'block',
          rule: verdict.rule?.id,
          severity: verdict.rule?.severity,
          reason: verdict.reason,
        },
        links: { result_of: requested.id, policy_decision_for: requested.id },
        raw: { source_hook: 'cursor:beforeReadFile:deny' },
      })))
      const fb = formatBlockFeedback({
        action: 'READ_FILE',
        target: filePath,
        policyRule: verdict.rule?.id,
        reason: verdict.reason,
      })
      return deny(sessionId, recorded, fb)
    }

    return allow(sessionId, recorded)
  }

  if (name === 'beforeMCPExecution') {
    const toolName = String(event.tool_name ?? event.tool ?? 'mcp_unknown')
    const mapped = mapCursorToolName(toolName.startsWith('MCP:') || toolName.startsWith('mcp__')
      ? toolName
      : `MCP:${toolName}`)
    const args = parseToolInput(event.tool_input)
    const mcpMeta = isMcpToolName(mapped) ? parseMcpToolName(mapped) : undefined
    const mcpTrustLevel = mcpMeta ? recorder.mcpTrust.observe(mcpMeta.server) : undefined
    const sensitivity = classifyToolSensitivity(mapped, args)

    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: meta.agentId },
      tool: {
        name: mapped,
        sensitivity,
        provider: mcpMeta ? 'mcp' : 'cursor',
      },
      ...mcpMeta ? {
        mcp: { server: mcpMeta.server, tool: mcpMeta.tool, trust: mcpTrustLevel! },
      } : {},
      action: { type: 'tool.request', target: mapped, arguments: args },
      capability: { used: mapped },
      raw: { source_hook: 'cursor:beforeMCPExecution' },
    }))
    recorded.push(requested)

    if (mcpMeta) {
      recorded.push(recorder.record(baseEvent({
        event_type: 'mcp.tool_requested',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn: meta.turn,
        agent: { id: meta.agentId },
        tool: { name: mapped, provider: mcpMeta.server, sensitivity },
        mcp: { server: mcpMeta.server, tool: mcpMeta.tool, trust: mcpTrustLevel! },
        action: {
          type: 'mcp.tool',
          target: `${mcpMeta.server}/${mcpMeta.tool}`,
          arguments: args,
        },
        links: { parent_event: requested.id, tool_source: requested.id },
        raw: { source_hook: 'cursor:beforeMCPExecution:mcp' },
      })))
    }

    const verdict = policy.evaluateToolRequest(requested)
    recorded.push(verdict.event)
    if (verdict.decision === 'block') {
      recorded.push(recorder.record(baseEvent({
        event_type: 'tool.denied',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn: meta.turn,
        agent: { id: meta.agentId },
        tool: { name: mapped, sensitivity },
        action: requested.action,
        policy: {
          decision: 'block',
          rule: verdict.rule?.id,
          severity: verdict.rule?.severity,
          reason: verdict.reason,
        },
        links: { result_of: requested.id, policy_decision_for: requested.id },
        raw: { source_hook: 'cursor:beforeMCPExecution:deny' },
      })))
      return deny(sessionId, recorded, formatBlockFeedback({
        action: 'MCP_TOOL_USE',
        target: mapped,
        policyRule: verdict.rule?.id,
        reason: verdict.reason,
      }))
    }
    return allow(sessionId, recorded)
  }

  if (name === 'preToolUse') {
    const cursorTool = String(event.tool_name ?? 'unknown')
    // Shell is enforced on beforeShellExecution — avoid double-deny races; still record.
    if (cursorTool === 'Shell' || cursorTool === 'shell') {
      return allow(sessionId, recorded)
    }
    const mapped = mapCursorToolName(cursorTool)
    const args = parseToolInput(event.tool_input)
    const sensitivity = classifyToolSensitivity(mapped, args)
    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: meta.agentId },
      tool: {
        name: mapped,
        call_id: event.tool_use_id ? String(event.tool_use_id) : undefined,
        sensitivity,
        provider: 'cursor',
      },
      action: { type: 'tool.request', target: mapped, arguments: args },
      capability: { used: mapped },
      raw: { source_hook: 'cursor:preToolUse', notes: `cursor_tool=${cursorTool}` },
    }))
    recorded.push(requested)
    const verdict = policy.evaluateToolRequest(requested)
    recorded.push(verdict.event)
    if (verdict.decision === 'block') {
      recorded.push(recorder.record(baseEvent({
        event_type: 'tool.denied',
        harness: { name: HARNESS_NAME },
        session: { id: sessionId },
        turn: meta.turn,
        agent: { id: meta.agentId },
        tool: { name: mapped, sensitivity },
        action: requested.action,
        policy: {
          decision: 'block',
          rule: verdict.rule?.id,
          severity: verdict.rule?.severity,
          reason: verdict.reason,
        },
        links: { result_of: requested.id, policy_decision_for: requested.id },
        raw: { source_hook: 'cursor:preToolUse:deny' },
      })))
      return deny(sessionId, recorded, formatBlockFeedback({
        action: mapped.toUpperCase(),
        target: JSON.stringify(args).slice(0, 200),
        policyRule: verdict.rule?.id,
        reason: verdict.reason,
      }))
    }
    return allow(sessionId, recorded)
  }

  if (name === 'postToolUse' || name === 'afterMCPExecution') {
    const mapped = mapCursorToolName(String(event.tool_name ?? event.tool ?? 'unknown'))
    recorded.push(recorder.record(baseEvent({
      event_type: 'tool.completed',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: meta.agentId },
      tool: { name: mapped },
      action: { type: 'tool.result', target: mapped, arguments: {} },
      raw: { source_hook: `cursor:${name}` },
    })))
    return { response: {}, sessionId, events: recorded, blocked: false }
  }

  if (name === 'afterFileEdit') {
    recorded.push(recorder.record(baseEvent({
      event_type: 'tool.completed',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: meta.agentId },
      tool: { name: 'write' },
      action: {
        type: 'tool.result',
        target: 'write',
        arguments: { path: String(event.file_path ?? '') },
      },
      raw: { source_hook: 'cursor:afterFileEdit' },
    })))
    return { response: {}, sessionId, events: recorded, blocked: false }
  }

  // Observation-only: do not claim enforcement from this response.
  if (name === 'subagentStart') {
    const childId = String(event.subagent_id ?? `cursor-sub-${Date.now().toString(36)}`)
    recorded.push(recorder.record(baseEvent({
      event_type: 'subagent.spawned',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: {
        id: childId,
        parent_agent_id: meta.agentId,
      },
      action: {
        type: 'subagent.spawn',
        target: String(event.subagent_type ?? 'unknown'),
        arguments: {
          subagent_type: event.subagent_type,
          observation_only: true,
        },
      },
      raw: {
        source_hook: 'cursor:subagentStart',
        notes: 'observation-only; no block claim without side-effect proof',
      },
    })))
    // Always allow — observation-only constraint
    return allow(sessionId, recorded)
  }

  if (name === 'subagentStop') {
    recorded.push(recorder.record(baseEvent({
      event_type: 'subagent.ended',
      harness: { name: HARNESS_NAME },
      session: { id: sessionId },
      turn: meta.turn,
      agent: { id: String(event.subagent_id ?? 'cursor-sub') },
      raw: { source_hook: 'cursor:subagentStop' },
    })))
    // Never inject followup_message (would script autonomy)
    return { response: {}, sessionId, events: recorded, blocked: false }
  }

  if (name === 'stop') {
    return { response: {}, sessionId, events: recorded, blocked: false }
  }

  return { response: {}, sessionId, events: recorded, blocked: false }
}
