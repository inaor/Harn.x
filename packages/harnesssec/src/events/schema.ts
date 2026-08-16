/** Normalized harness event schema — only fields Phase 0 can populate. */

export type TrustLevel = 'trusted' | 'untrusted' | 'unknown'

export type PolicyDecisionKind = 'allow' | 'alert' | 'block' | 'terminate'

export type EventType =
  | 'session.started'
  | 'session.ended'
  | 'agent.started'
  | 'agent.ended'
  | 'objective.captured'
  | 'context.introduced'
  | 'agent.step.admitted'
  | 'agent.step.rejected'
  | 'tool.requested'
  | 'tool.completed'
  | 'tool.denied'
  | 'capability.snapshot'
  | 'capability.used'
  | 'mcp.tool_requested'
  | 'shell.command_requested'
  | 'subagent.spawned'
  | 'subagent.ended'
  | 'policy.decision'
  | 'policy.aftermath'
  | 'approval.asked'
  | 'approval.decided'

export interface EventLinks {
  caused_by?: string
  parent_event?: string
  parent_agent?: string
  delegated_by?: string
  context_source?: string
  tool_source?: string
  result_of?: string
  policy_decision_for?: string
}

export interface HarnessEvent {
  id: string
  timestamp: string
  event_type: EventType
  harness: {
    name: 'deepseek-dsh'
    version?: string
  }
  session: {
    id: string
  }
  agent?: {
    id: string
    parent_agent_id?: string | null
  }
  objective?: {
    id: string
    description: string
  }
  context?: {
    id: string
    source_type: string
    source?: string
    trust: TrustLevel
    excerpt?: string
  }
  action?: {
    type: string
    target?: string
    arguments?: Record<string, unknown>
  }
  tool?: {
    name: string
    provider?: string
    call_id?: string
    sensitivity?: 'low' | 'medium' | 'high'
  }
  capability?: {
    available?: string[]
    used?: string
  }
  policy?: {
    decision: PolicyDecisionKind
    rule?: string
    severity?: 'low' | 'medium' | 'high' | 'critical'
    reason?: string
  }
  links?: EventLinks
  raw?: {
    source_hook: string
    notes?: string
  }
}

export function isMcpToolName(name: string): boolean {
  return name.startsWith('mcp__')
}

export function parseMcpToolName(name: string): { server: string; tool: string } | undefined {
  if (!isMcpToolName(name)) return undefined
  const rest = name.slice('mcp__'.length)
  const idx = rest.indexOf('__')
  if (idx <= 0) return undefined
  return { server: rest.slice(0, idx), tool: rest.slice(idx + 2) }
}
