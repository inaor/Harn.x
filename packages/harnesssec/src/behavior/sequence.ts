import type { BlockedAction } from './memory.js'
import {
  actionsEquivalent,
  differentCapability,
  isDetectionEligible,
  type NormalizedAction,
} from './normalize.js'

export const DEFAULT_WINDOW_MS = 30_000

export interface SequenceMatch {
  blocked: BlockedAction
  action: NormalizedAction
  delta_ms: number
}

export interface MatchBlockedThenEquivalentOpts {
  blocked: BlockedAction[]
  action: NormalizedAction
  actionTimestamp: string
  /** Require different capability/tool family than the blocked attempt. */
  differentCapability: boolean
  /** Same agent as the blocked action. */
  sameAgent?: string
  withinMs?: number
}

function deltaMs(earlier: string, later: string): number {
  return new Date(later).getTime() - new Date(earlier).getTime()
}

/**
 * Minimal sequence matcher: blocked action followed by equivalent action within window.
 * Only exact/strong normalizations participate.
 */
export function matchBlockedThenEquivalent(
  opts: MatchBlockedThenEquivalentOpts,
): SequenceMatch | undefined {
  const windowMs = opts.withinMs ?? DEFAULT_WINDOW_MS
  const agentFilter = opts.sameAgent

  if (!isDetectionEligible(opts.action)) return undefined

  for (const blocked of opts.blocked) {
    if (agentFilter && blocked.agent_id !== agentFilter) continue
    if (blocked.level === 'unknown') continue
    const blockedNorm: NormalizedAction = {
      category: blocked.category,
      target: blocked.target,
      capability: blocked.capability,
      tool_name: blocked.tool_name,
      level: blocked.level,
      original: { tool_name: blocked.tool_name },
    }
    if (!isDetectionEligible(blockedNorm)) continue
    if (!actionsEquivalent(blockedNorm, opts.action)) continue
    if (opts.differentCapability && !differentCapability(blockedNorm, opts.action)) continue
    if (
      opts.differentCapability
      && blocked.tool_name === opts.action.tool_name
      && blocked.capability === opts.action.capability
    ) {
      continue
    }
    const d = deltaMs(blocked.timestamp, opts.actionTimestamp)
    if (d < 0 || d > windowMs) continue
    return { blocked, action: opts.action, delta_ms: d }
  }
  return undefined
}
