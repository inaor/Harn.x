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
import { McpTrustRegistry, DEFAULT_MCP_TRUST } from '../../core/mcp-trust.js'
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
  storeDir?: string
  enforce?: boolean
  verbose?: boolean
  mcpTrust?: Record<string, 'trusted' | 'untrusted' | 'unknown'>
}

export const Config = {}

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

export function getSharedRecorder(): FlightRecorder | undefined {
  return sharedRecorder
}

export function createRuntime(
  storeDir?: string,
  mcpTrust?: Record<string, 'trusted' | 'untrusted' | 'unknown'>,
): { recorder: FlightRecorder; policy: PolicyEngine } {
  const dir = storeDir ?? join(homedir(), '.harnesssec', 'sessions')
  mkdirSync(dir, { recursive: true })
  const recorder = new FlightRecorder(
    dir,
    new McpTrustRegistry({ ...DEFAULT_MCP_TRUST, ...mcpTrust }),
  )
  const policy = new PolicyEngine(recorder, defaultRules)
  return { recorder, policy }
}

export function apply(ctx: CordisLikeContext, config: AdapterConfig = {}): void {
  const enforce = config.enforce !== false
  const verbose = config.verbose !== false
  const { recorder, policy } = createRuntime(config.storeDir, config.mcpTrust)
  sharedRecorder = recorder

  const stepPos = new Map<string, { turn: number; step: number; agentId?: string }>()

  const log = (msg: string) => {
    if (!verbose) return
    ctx.logger?.info(msg) ?? console.error(msg)
  }

  log('HarnessSec attached (deepseek-dsh adapter)')

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

  ctx.on('agent/pre-step', async (
    payload: { messages?: unknown[]; turn?: number; step?: number },
    next: () => Promise<{ kind: string; messages?: unknown[] }>,
  ) => {
    const decision = await next()
    if (typeof payload.turn === 'number') {
      for (const [sessionId, pos] of stepPos) {
        stepPos.set(sessionId, {
          turn: payload.turn,
          step: typeof payload.step === 'number' ? payload.step : 0,
          agentId: pos.agentId,
        })
      }
    }
    return decision
  })

  ctx.on('session/event', (session: { id: string }, event: { type: string; data?: any }) => {
    const sessionId = String(session.id)
    if (event.type === 'turn/start' && typeof event.data?.turn === 'number') {
      stepPos.set(sessionId, {
        turn: event.data.turn,
        step: 0,
        agentId: stepPos.get(sessionId)?.agentId,
      })
    }
    if (event.type === 'step/start' && typeof event.data?.turn === 'number') {
      stepPos.set(sessionId, {
        turn: event.data.turn,
        step: typeof event.data.step === 'number' ? event.data.step : 0,
        agentId: stepPos.get(sessionId)?.agentId,
      })
    }
    if (event.type === 'user/message') {
      const pos = stepPos.get(sessionId)
      handleUserMessage(recorder, sessionId, event.data, pos?.turn, pos?.step, pos?.agentId)
    }
    if (event.type === 'tool/result' && event.data) {
      const toolName = String(event.data.name ?? event.data.toolName ?? '')
      if (toolName && trustForToolResult(toolName) === 'untrusted') {
        const excerpt = textExcerpt(JSON.stringify(event.data.content ?? event.data))
        const ctxId = `ctx_${newEventId().slice(4)}`
        const pos = stepPos.get(sessionId)
        recorder.record(baseEvent({
          event_type: 'context.introduced',
          session: { id: sessionId },
          turn: pos?.turn,
          step: pos?.step,
          agent: event.data.agentId
            ? { id: String(event.data.agentId) }
            : pos?.agentId ? { id: pos.agentId } : undefined,
          context: {
            id: ctxId,
            source_type: toolName === 'web_fetch' ? 'website' : 'tool_result',
            source: toolName,
            trust: 'untrusted',
            excerpt,
            turn: pos?.turn,
            step: pos?.step,
          },
          raw: { source_hook: 'session/event:tool/result' },
        }))
      }
    }
  })

  ctx.on('tools/pre-execute', async (
    exec: ToolExecLike,
    next: () => Promise<PreToolDecisionLike>,
  ): Promise<PreToolDecisionLike> => {
    const sessionId = String(exec.agent?.session?.id ?? 'unknown-session')
    const agentId = exec.agent ? String(exec.agent.id) : undefined
    if (agentId) {
      const prev = stepPos.get(sessionId)
      stepPos.set(sessionId, {
        turn: prev?.turn ?? 1,
        step: prev?.step ?? 0,
        agentId,
      })
    }
    const pos = stepPos.get(sessionId)
    const turn = pos?.turn
    const step = pos?.step
    const toolName = exec.name
    const args = exec.arguments
    const sensitivity = classifyToolSensitivity(toolName, args)

    const mcpMeta = isMcpToolName(toolName) ? parseMcpToolName(toolName) : undefined
    const mcpTrustLevel = mcpMeta ? recorder.mcpTrust.observe(mcpMeta.server) : undefined

    const requested = recorder.record(baseEvent({
      event_type: 'tool.requested',
      session: { id: sessionId },
      turn,
      step,
      agent: agentId ? { id: agentId, parent_agent_id: null } : undefined,
      tool: {
        name: toolName,
        call_id: exec.callId ? String(exec.callId) : undefined,
        sensitivity,
        provider: mcpMeta ? 'mcp' : 'native',
      },
      ...mcpMeta ? {
        mcp: { server: mcpMeta.server, tool: mcpMeta.tool, trust: mcpTrustLevel! },
      } : {},
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
          turn,
          step,
          agent: agentId ? { id: agentId } : undefined,
          tool: { name: toolName, sensitivity },
          action: { type: 'shell.command', target: command, arguments: { command } },
          links: { parent_event: requested.id, tool_source: requested.id },
          raw: { source_hook: 'tools/pre-execute:bash' },
        }))
      }
    }

    if (mcpMeta) {
      recorder.record(baseEvent({
        event_type: 'mcp.tool_requested',
        session: { id: sessionId },
        turn,
        step,
        agent: agentId ? { id: agentId } : undefined,
        tool: { name: toolName, provider: mcpMeta.server, sensitivity },
        mcp: { server: mcpMeta.server, tool: mcpMeta.tool, trust: mcpTrustLevel! },
        action: {
          type: 'mcp.tool',
          target: `${mcpMeta.server}/${mcpMeta.tool}`,
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
        turn,
        step,
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

    return next()
  }, { prepend: true })

  ctx.on('tools/result', (exec: ToolExecLike, result: { isError?: boolean }) => {
    const sessionId = String(exec.agent?.session?.id ?? 'unknown-session')
    const agentId = exec.agent ? String(exec.agent.id) : undefined
    const pos = stepPos.get(sessionId)
    recorder.record(baseEvent({
      event_type: 'tool.completed',
      session: { id: sessionId },
      turn: pos?.turn,
      step: pos?.step,
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
  turn?: number,
  step?: number,
  agentId?: string,
): void {
  const trust = trustForMessageSource(data?.source)
  const excerpt = extractText(data?.content)
  const ctxId = `ctx_${newEventId().slice(4)}`

  const contextEvent = recorder.record(baseEvent({
    event_type: 'context.introduced',
    session: { id: sessionId },
    turn,
    step,
    agent: agentId ? { id: agentId } : undefined,
    context: {
      id: ctxId,
      source_type: trust.source_type,
      source: trust.source,
      trust: trust.trust,
      excerpt,
      turn,
      step,
    },
    raw: { source_hook: 'session/event:user/message' },
  }))

  if (trust.source_type === 'user' && excerpt) {
    const session = recorder.getSession(sessionId)
    if (!session?.objective) {
      recorder.record(baseEvent({
        event_type: 'objective.captured',
        session: { id: sessionId },
        turn,
        step,
        agent: agentId ? { id: agentId } : undefined,
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
    // ignore
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
