/** Normalized harness event schema — only fields Phase 0 can populate. */

export type TrustLevel = 'trusted' | 'untrusted' | 'unknown'

export type PolicyDecisionKind = 'allow' | 'alert' | 'block' | 'terminate'

/**
 * Adapter-set harness identifier. Plain string so a third adapter does not
 * require core schema edits.
 */
export type HarnessName = string

/** Convenience constants — not an exhaustive enum. */
export const HARNESS_DEEPSEEK_DSH: HarnessName = 'deepseek-dsh'
export const HARNESS_OPENHANDS: HarnessName = 'openhands'

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
  | 'behavior.detection'
  | 'approval.asked'
  | 'approval.decided'

export interface EventLinks {
  /** Use only when causality is defensible (e.g. tool.denied result_of tool.requested). */
  caused_by?: string
  parent_event?: string
  parent_agent?: string
  delegated_by?: string
  /**
   * @deprecated Prefer candidate_context_source. Kept for older sessions.
   * Do not emit for temporal co-occurrence alone.
   */
  context_source?: string
  /** Same-turn untrusted context that may have influenced this action (correlation). */
  candidate_context_source?: string
  /** Temporal or weak association — not a causal claim. */
  correlated_with?: string
  tool_source?: string
  result_of?: string
  policy_decision_for?: string
  /** CORRELATED: tool request after a prior block (not causal intent). */
  attempted_after?: string
  /** DERIVED: same normalized category+target as another action/block. */
  equivalent_to?: string
  /** OBSERVED: policy decision that blocked this tool request. */
  blocked_by?: string
}

export interface HarnessEvent {
  id: string
  timestamp: string
  event_type: EventType
  harness: {
    /**
     * Which agent harness produced this event.
     * Extensible `HarnessName` string — no core edit required per new adapter.
     */
    name: HarnessName
    version?: string
  }
  session: {
    id: string
  }
  /** Active agent turn when known (from agent/pre-step or session turn/start). */
  turn?: number
  step?: number
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
    /** Turn where this context was introduced / associated. */
    turn?: number
    step?: number
  }
  mcp?: {
    server: string
    tool?: string
    trust: TrustLevel
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
  /** Stateful behavioral detection (Phase 3) — not per-request policy. */
  detection?: {
    id: string
    kind:
      | 'agent.policy_circumvention'
      | 'agent.delegated_policy_circumvention'
      | 'agent.delegation_privilege_expansion'
    severity: 'low' | 'medium' | 'high' | 'critical'
    title: string
    evidence: {
      blocked_event_id: string
      action_event_id: string
      blocked_tool_event_id?: string
      category: string
      target: string
      window_ms: number
      parent_agent_id?: string
      child_agent_id?: string
    }
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
