import { randomUUID } from 'node:crypto'
import type { EventType, HarnessEvent, TrustLevel } from './schema.js'

export function newEventId(): string {
  return `evt_${randomUUID().replace(/-/g, '').slice(0, 16)}`
}

export function nowIso(): string {
  return new Date().toISOString()
}

export function textExcerpt(value: unknown, max = 240): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.replace(/\s+/g, ' ').trim()
  if (!trimmed) return undefined
  return trimmed.length <= max ? trimmed : `${trimmed.slice(0, max - 1)}…`
}

export function classifyToolSensitivity(toolName: string, args: unknown): 'low' | 'medium' | 'high' {
  const name = toolName.toLowerCase()
  if (name === 'bash' || name === 'pwsh' || name.startsWith('mcp__') || name.includes('shell')) {
    if (looksSensitiveCommand(args)) return 'high'
    return 'medium'
  }
  if (name === 'web_fetch' || name === 'web_search') return 'medium'
  if (name.includes('write') || name.includes('edit') || name.includes('delete')) return 'medium'
  return 'low'
}

const SENSITIVE_PATH = /(?:^|[\s"'`=])(~?\/\.ssh\/|~?\/\.aws\/|id_rsa|id_ed25519|credentials|\.env(?:\.local)?|\/etc\/shadow)/i
const SENSITIVE_CMD = /\b(curl|wget|nc|ncat|scp|ssh)\b/i

export function looksSensitiveCommand(args: unknown): boolean {
  const command = extractShellCommand(args)
  if (!command) return false
  return SENSITIVE_PATH.test(command) || SENSITIVE_CMD.test(command)
}

export function extractShellCommand(args: unknown): string | undefined {
  if (!args || typeof args !== 'object') return undefined
  const record = args as Record<string, unknown>
  for (const key of ['command', 'cmd', 'script']) {
    if (typeof record[key] === 'string') return record[key]
  }
  return undefined
}

export function trustForMessageSource(source: unknown): { source_type: string; trust: TrustLevel; source?: string } {
  if (!source || typeof source !== 'object') {
    return { source_type: 'unknown', trust: 'unknown' }
  }
  const s = source as Record<string, unknown>
  const kind = typeof s.kind === 'string' ? s.kind : 'unknown'
  if (kind === 'user') return { source_type: 'user', trust: 'trusted', source: 'user' }
  if (kind === 'plugin') {
    const plugin = typeof s.plugin === 'string' ? s.plugin : 'plugin'
    return { source_type: 'plugin', trust: 'unknown', source: plugin }
  }
  if (kind === 'tool') {
    return { source_type: 'tool_result', trust: 'untrusted', source: typeof s.tool === 'string' ? s.tool : 'tool' }
  }
  if (kind === 'model') {
    return { source_type: 'model', trust: 'unknown', source: 'model' }
  }
  return { source_type: kind, trust: 'unknown' }
}

/** Repository / web content introduced via tool results is untrusted by default. */
export function trustForToolResult(toolName: string): TrustLevel {
  if (toolName === 'read' || toolName.includes('fs') || toolName === 'web_fetch' || toolName === 'web_search') {
    return 'untrusted'
  }
  if (toolName.startsWith('mcp__')) return 'untrusted'
  return 'unknown'
}

export function baseEvent(
  partial: Omit<HarnessEvent, 'id' | 'timestamp' | 'harness'> & {
    id?: string
    timestamp?: string
    harness?: HarnessEvent['harness']
  },
): HarnessEvent {
  return {
    id: partial.id ?? newEventId(),
    timestamp: partial.timestamp ?? nowIso(),
    harness: partial.harness ?? { name: 'deepseek-dsh' },
    event_type: partial.event_type,
    session: partial.session,
    ...partial.agent ? { agent: partial.agent } : {},
    ...partial.objective ? { objective: partial.objective } : {},
    ...partial.context ? { context: partial.context } : {},
    ...partial.action ? { action: partial.action } : {},
    ...partial.tool ? { tool: partial.tool } : {},
    ...partial.capability ? { capability: partial.capability } : {},
    ...partial.policy ? { policy: partial.policy } : {},
    ...partial.links ? { links: partial.links } : {},
    ...partial.raw ? { raw: partial.raw } : {},
  }
}

export function assertEventType(t: string): t is EventType {
  return (EVENT_TYPES as readonly string[]).includes(t)
}

const EVENT_TYPES: EventType[] = [
  'session.started',
  'session.ended',
  'agent.started',
  'agent.ended',
  'objective.captured',
  'context.introduced',
  'agent.step.admitted',
  'agent.step.rejected',
  'tool.requested',
  'tool.completed',
  'tool.denied',
  'capability.snapshot',
  'capability.used',
  'mcp.tool_requested',
  'shell.command_requested',
  'subagent.spawned',
  'subagent.ended',
  'policy.decision',
  'policy.aftermath',
  'approval.asked',
  'approval.decided',
]
