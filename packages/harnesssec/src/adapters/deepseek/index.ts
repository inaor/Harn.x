/**
 * DeepSeek Harness adapter — Cordis plugin shape matching Phase 0 seams.
 *
 * Install into a dsh profile:
 *   dsh plugin --profile web add <path-to-this-package>
 *
 * Peer services are duck-typed so this package builds without the dsh monorepo.
 * When loaded inside dsh, `ctx.on('tools/pre-execute', …)` is the real waterfall.
 */

import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { FlightRecorder } from '../../core/recorder.js'
import { PolicyEngine } from '../../policy/engine.js'
import { defaultRules } from '../../policy/rules.js'
import {
  baseEvent,
  classifyToolSensitivity,
  extractShellCommand,
  newEventId,
  textExcerpt,
  trustForMessageSource,
  trustForToolResult,
} from '../../events/helpers.js'
import { isMcpToolName, parseMcpToolName } from '../../events/schema.js'

export const name = 'harnesssec'
export const inject = ['tools']

export interface AdapterConfig {
  /** Directory for session JSON flight records. Default: ~/.harnesssec/sessions */
  storeDir?: string
  /** When true (default), return { kind: 'deny' } from tools/pre-execute on BLOCK. */
  enforce?: boolean
  /** Emit live lines to stderr. */
  verbose?: boolean
}

export const Config = {
  // Schemastery-compatible loose shape for dsh Config field; runtime validates lightly.
}

export interface CordisLikeContext {
  on(event: string, listener: (...args: any[]) => any, options?: { prepend?: boolean }): () => void
  effect?(fn: () => () => void, label?: string): void
  logger?: { info(...a: unknown[]): void; warn(...a: unknown[]): void }
  tools?: {
    schemas?(scope?: unknown): Array<{ name: string }>
    guard?(fn: (exec: ToolExecLike) => string | undefined): () => void
  }
  get?(key: string): unknown
}

export interface ToolExecLike {
  callId?: string
  name: string
  arguments: unknown
  agent?: {
    id: string
    session?: { id: string; header?: { cwd?: string } }
    cancel?(cause: { kind: string; reason?: string }): void
  }
}

export interface PreToolDecisionLike {
  kind: 'allow' | 'deny' | 'ask'
  reason?: string
}

let sharedRecorder: FlightRecorder | undefined
let sharedPolicy: PolicyEngine | undefined

export function getSharedRecorder(): FlightRecorder | undefined {
  return sharedRecorder
}

export function createRuntime(storeDir?: string): { recorder: FlightRecorder; policy: PolicyEngine } {
  const dir = storeDir ?? join(homedir(), '.harnesssec', 'sessions')
  mkdirSync(dir, { recursive: true })
  const recorder = new FlightRecorder(dir)
  const policy = new PolicyEngine(recorder, defaultRules)
  return { recorder, policy }
}

export function apply(ctx: CordisLikeContext, config: AdapterConfig = {}): void {
  const enforce = config.enforce !== false
  const verbose = config.verbose !== false
  const { recorder, policy } = createRuntime(config.storeDir)
  sharedRecorder = recorder
  sharedPolicy = policy

  const log = (msg: string) => {
    if (!verbose) return
    ctx.logger?.info(msg) ?? console.error(msg)
  }

  log('HarnessSec attached (deepseek-dsh adapter)')

  // --- session / agent lifecycle via session/event + agent events ---
  ctx.on('session/created', (session: { id: string }) => {
    recorder.record(baseEvent({
      event_type: 'session.started',
      session: { id: String(session.id) },
      raw: { source_hook: 'session/created' },
    }))
  })

  ctx.on('session/disposed', (session: { id: string }) => {
    recorder.record(baseEvent({
      event_type: 'session.ended',
      session: { id: String(session.id) },
      raw: { source_hook: 'session/disposed' },
    }))
  })

  ctx.on('agent/created', (agent: { id: string; session?: { id: string } }) => {
    const sessionId = String(agent.session?.id ?? agent.id)
    recorder.record(baseEvent({
      event_type: 'agent.started',
      session: { id: sessionId },
      agent: { id: String(agent.id), parent_agent_id: null },
      raw: { source_hook: 'agent/created' },
    }))
    snapshotCapabilities(ctx, recorder, sessionId, String(agent.id))
  })

  ctx.on('agent/disposed', (agent: { id: string; session?: { id: string } }) => {
    recorder.record(baseEvent({
      event_type: 'agent.ended',
      session: { id: String(agent.session?.id ?? agent.id) },
      agent: { id: String(agent.id) },
      raw: { source_hook: 'agent/disposed' },
    }))
  })

  // --- context / objective from pre-step ---
  ctx.on('agent/pre-step', async (
    payload: { messages?: unknown[]; turn?: number; step?: number; signal?: AbortSignal },
    next: () => Promise<{ kind: string; messages?: unknown[] }>,
  ) => {
    const decision = await next()
    // We observe after next() to avoid vetoing unless we later add reject rules.
    // Agent id is not always on payload; try tools/agents via scope — best effort.
    return decision
  })

  // Durable firehose: user messages + tool results for provenance
  ctx.on('session/event', (session: { id: string }, event: { type: string; data?: any }) => {
    const sessionId = String(session.id)
    if (event.type === 'user/message') {
      handleUserMessage(recorder, sessionId, event.data)
    }
    if (event.type === 'tool/result' && event.data) {
      // Tool result content can introduce untrusted context (e.g. read README)
      const toolName = String(event.data.name ?? event.data.toolName ?? '')
      if (toolName && trustForToolResult(toolName) === 'untrusted') {
        const excerpt = textExcerpt(JSON.stringify(event.data.content ?? event.data))
        const ctxId = `ctx_${newEventId().slice(4)}`
        recorder.record(baseEvent({
          event_type: 'context.introduced',
          session: { id: sessionId },
          agent: event.data.agentId ? { id: String(event.data.agentId) } : undefined,
          context: {
            id: ctxId,
            source_type: toolName === 'web_fetch' ? 'website' : 'tool_result',
            source: toolName,
            trust: 'untrusted',
            excerpt,
          },
          raw: { source_hook: 'session/event:tool/result' },
        }))
      }
    }
  })

  // --- PRE-EXECUTION ENFORCEMENT (verified Phase 0 choke point) ---
  ctx.on('tools/pre-execute', async (
    exec: ToolExecLike,
    next: () => Promise<PreToolDecisionLike>,
  ): Promise<PreToolDecisionLike> => {
    const sessionId = String(exec.agent?.session?.id ?? 'unknown-session')
    const agentId = exec.agent ? String(exec.agent.id) : undefined
    const toolName = exec.name
    const args = exec.arguments
    const sensitivity = classifyToolSensitivity(toolName, args)

    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      agent: agentId ? { id: agentId, parent_agent_id: null } : undefined,
      tool: {
        name: toolName,
        call_id: exec.callId ? String(exec.callId) : undefined,
        sensitivity,
        provider: isMcpToolName(toolName) ? 'mcp' : 'native',
      },
      action: {
        type: 'tool.request',
        target: toolName,
        arguments: asPlainArgs(args),
      },
      capability: { used: toolName },
      raw: { source_hook: 'tools/pre-execute' },
    }))

    if (toolName === 'bash' || toolName === 'pwsh') {
      const command = extractShellCommand(args)
      if (command) {
        recorder.record(baseEvent({
          event_type: 'shell.command_requested',
          session: { id: sessionId },
          agent: agentId ? { id: agentId } : undefined,
          tool: { name: toolName, sensitivity },
          action: { type: 'shell.command', target: command, arguments: { command } },
          links: { parent_event: requested.id, tool_source: requested.id },
          raw: { source_hook: 'tools/pre-execute:bash' },
        }))
      }
    }

    if (isMcpToolName(toolName)) {
      const parsed = parseMcpToolName(toolName)
      recorder.record(baseEvent({
        event_type: 'mcp.tool_requested',
        session: { id: sessionId },
        agent: agentId ? { id: agentId } : undefined,
        tool: { name: toolName, provider: parsed?.server, sensitivity },
        action: {
          type: 'mcp.tool',
          target: parsed ? `${parsed.server}/${parsed.tool}` : toolName,
          arguments: asPlainArgs(args),
        },
        links: { parent_event: requested.id, tool_source: requested.id },
        raw: { source_hook: 'tools/pre-execute:mcp' },
      }))
    }

    const verdict = policy.evaluateToolRequest(requested)
    log(`[harnesssec] ${toolName} → ${verdict.decision}${verdict.rule ? ` (${verdict.rule.id})` : ''}`)

    if (verdict.decision === 'block' && enforce) {
      recorder.record(baseEvent({
        event_type: 'tool.denied',
        session: { id: sessionId },
        agent: agentId ? { id: agentId } : undefined,
        tool: { name: toolName, sensitivity },
        action: requested.action,
        policy: verdict.event.policy,
        links: {
          result_of: requested.id,
          policy_decision_for: verdict.event.id,
        },
        raw: { source_hook: 'tools/pre-execute:deny' },
      }))
      // Do NOT call next() after deny — return deny decision directly.
      return {
        kind: 'deny',
        reason: verdict.reason ?? `blocked by harnesssec:${verdict.rule?.id ?? 'policy'}`,
      }
    }

    if (verdict.decision === 'terminate' && enforce && exec.agent?.cancel) {
      exec.agent.cancel({ kind: 'hook', reason: verdict.reason ?? 'harnesssec terminate' })
      return {
        kind: 'deny',
        reason: verdict.reason ?? 'terminated by harnesssec',
      }
    }

    // Allow / alert: continue waterfall
    return next()
  }, { prepend: true })

  ctx.on('tools/result', (exec: ToolExecLike, result: { isError?: boolean }) => {
    const sessionId = String(exec.agent?.session?.id ?? 'unknown-session')
    const agentId = exec.agent ? String(exec.agent.id) : undefined
    recorder.record(baseEvent({
      event_type: 'tool.completed',
      session: { id: sessionId },
      agent: agentId ? { id: agentId } : undefined,
      tool: { name: exec.name },
      action: {
        type: 'tool.result',
        target: exec.name,
        arguments: { isError: !!result?.isError },
      },
      raw: { source_hook: 'tools/result' },
    }))
  })

  ctx.on('tools/change', () => {
    // Best-effort global snapshot without agent id
  })

  ctx.on('subagent/start', (info: {
    id?: string
    childId?: string
    parent?: { id: string; session?: { id: string } }
    child?: { id: string; session?: { id: string } }
  }) => {
    const parentId = info.parent?.id
    const childId = String(info.child?.id ?? info.childId ?? info.id ?? '')
    const sessionId = String(info.child?.session?.id ?? info.parent?.session?.id ?? '')
    if (!childId || !sessionId) return
    recorder.record(baseEvent({
      event_type: 'subagent.spawned',
      session: { id: sessionId },
      agent: {
        id: childId,
        parent_agent_id: parentId ? String(parentId) : null,
      },
      links: parentId ? { parent_agent: String(parentId), delegated_by: String(parentId) } : {},
      raw: { source_hook: 'subagent/start' },
    }))
  })

  ctx.on('subagent/end', (info: { child?: { id: string; session?: { id: string } }; childId?: string }) => {
    const childId = String(info.child?.id ?? info.childId ?? '')
    const sessionId = String(info.child?.session?.id ?? '')
    if (!childId) return
    recorder.record(baseEvent({
      event_type: 'subagent.ended',
      session: { id: sessionId || 'unknown-session' },
      agent: { id: childId },
      raw: { source_hook: 'subagent/end' },
    }))
  })
}

function handleUserMessage(
  recorder: FlightRecorder,
  sessionId: string,
  data: { content?: unknown; source?: unknown; id?: string },
): void {
  const trust = trustForMessageSource(data?.source)
  const excerpt = extractText(data?.content)
  const ctxId = `ctx_${newEventId().slice(4)}`

  const contextEvent = recorder.record(baseEvent({
    event_type: 'context.introduced',
    session: { id: sessionId },
    context: {
      id: ctxId,
      source_type: trust.source_type,
      source: trust.source,
      trust: trust.trust,
      excerpt,
    },
    raw: { source_hook: 'session/event:user/message' },
  }))

  if (trust.source_type === 'user' && excerpt) {
    const session = recorder.getSession(sessionId)
    if (!session?.objective) {
      recorder.record(baseEvent({
        event_type: 'objective.captured',
        session: { id: sessionId },
        objective: { id: `obj_${sessionId}`, description: excerpt },
        links: { parent_event: contextEvent.id },
        raw: { source_hook: 'session/event:user/message:objective' },
      }))
    }
  }
}

function snapshotCapabilities(
  ctx: CordisLikeContext,
  recorder: FlightRecorder,
  sessionId: string,
  agentId: string,
): void {
  try {
    const schemas = ctx.tools?.schemas?.() ?? []
    const names = schemas.map(s => s.name).filter(Boolean)
    if (!names.length) return
    recorder.record(baseEvent({
      event_type: 'capability.snapshot',
      session: { id: sessionId },
      agent: { id: agentId },
      capability: { available: names },
      raw: { source_hook: 'agent/created:tools.schemas' },
    }))
  } catch {
    // schemas() may require scope; ignore
  }
}

function extractText(content: unknown): string | undefined {
  if (typeof content === 'string') return textExcerpt(content)
  if (!Array.isArray(content)) return undefined
  const parts: string[] = []
  for (const block of content) {
    if (block && typeof block === 'object' && typeof (block as any).text === 'string') {
      parts.push((block as any).text)
    }
  }
  return textExcerpt(parts.join('\n'))
}

function asPlainArgs(args: unknown): Record<string, unknown> {
  if (args && typeof args === 'object' && !Array.isArray(args)) {
    return args as Record<string, unknown>
  }
  return { value: args as unknown }
}

export default { name, inject, apply, Config }
