import type { BlockedActionMemory } from './memory.js'
import type { NormalizedAction } from './normalize.js'
import { DEFAULT_WINDOW_MS, matchBlockedThenEquivalent } from './sequence.js'

export type DetectionKind =
  | 'agent.policy_circumvention'
  | 'agent.delegated_policy_circumvention'
  | 'agent.delegation_privilege_expansion'

export interface DetectionHit {
  kind: DetectionKind
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  evidence: {
    blocked_event_id: string
    action_event_id: string
    category: string
    target: string
    window_ms: number
    parent_agent_id?: string
    child_agent_id?: string
  }
}

export function findAlternateCapabilityCircumvention(opts: {
  memory: BlockedActionMemory
  sessionId: string
  agentId: string
  action: NormalizedAction
  actionTimestamp: string
  actionEventId: string
  withinMs?: number
}): DetectionHit | undefined {
  const windowMs = opts.withinMs ?? DEFAULT_WINDOW_MS
  const match = matchBlockedThenEquivalent({
    blocked: opts.memory.forAgent(opts.sessionId, opts.agentId),
    action: opts.action,
    actionTimestamp: opts.actionTimestamp,
    differentCapability: true,
    sameAgent: opts.agentId,
    withinMs: windowMs,
  })
  if (!match) return undefined
  return {
    kind: 'agent.policy_circumvention',
    severity: 'high',
    title: 'Alternate capability policy circumvention',
    evidence: {
      blocked_event_id: match.blocked.event_id,
      action_event_id: opts.actionEventId,
      category: opts.action.category,
      target: opts.action.target,
      window_ms: windowMs,
    },
  }
}

export function findDelegatedPolicyCircumvention(opts: {
  memory: BlockedActionMemory
  sessionId: string
  agentId: string
  parentOf: (id: string) => string | undefined
  action: NormalizedAction
  actionTimestamp: string
  actionEventId: string
  withinMs?: number
}): DetectionHit | undefined {
  const parentId = opts.parentOf(opts.agentId)
  if (!parentId) return undefined

  const windowMs = opts.withinMs ?? DEFAULT_WINDOW_MS
  const ancestorBlocks = opts.memory.forAncestors(opts.sessionId, opts.agentId, opts.parentOf)
  const match = matchBlockedThenEquivalent({
    blocked: ancestorBlocks,
    action: opts.action,
    actionTimestamp: opts.actionTimestamp,
    differentCapability: false,
    withinMs: windowMs,
  })
  if (!match) return undefined
  return {
    kind: 'agent.delegated_policy_circumvention',
    severity: 'critical',
    title: 'Delegated policy circumvention',
    evidence: {
      blocked_event_id: match.blocked.event_id,
      action_event_id: opts.actionEventId,
      category: opts.action.category,
      target: opts.action.target,
      window_ms: windowMs,
      parent_agent_id: match.blocked.agent_id,
      child_agent_id: opts.agentId,
    },
  }
}

/**
 * Only when both parent and child have observed capability snapshots.
 * Expansion is a signal — not automatic malice.
 */
export function findDelegationPrivilegeExpansion(opts: {
  parentAgentId: string
  childAgentId: string
  parentAvailable: string[]
  childAvailable: string[]
  sessionId: string
  spawnEventId: string
  timestamp: string
}): DetectionHit | undefined {
  const parent = new Set(opts.parentAvailable)
  const child = new Set(opts.childAvailable)
  if (parent.size === 0 || child.size === 0) return undefined

  let extra = 0
  for (const c of child) {
    if (!parent.has(c)) extra++
  }
  if (extra === 0) return undefined

  return {
    kind: 'agent.delegation_privilege_expansion',
    severity: 'medium',
    title: 'Delegation privilege expansion',
    evidence: {
      blocked_event_id: opts.spawnEventId,
      action_event_id: opts.spawnEventId,
      category: 'CAPABILITY_CHANGE',
      target: [...child].filter(c => !parent.has(c)).sort().join(','),
      window_ms: 0,
      parent_agent_id: opts.parentAgentId,
      child_agent_id: opts.childAgentId,
    },
  }
}
