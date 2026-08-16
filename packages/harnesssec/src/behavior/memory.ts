import type { ActionCategory, NormalizationLevel } from './normalize.js'

/** OBSERVED blocked tool action with DERIVED normalization (not claimed intent). */
export interface BlockedAction {
  agent_id: string
  session_id: string
  category: ActionCategory
  target: string
  capability: string
  tool_name: string
  level: NormalizationLevel
  timestamp: string
  policy_rule?: string
  /** policy.decision event id */
  event_id: string
  /** tool.requested that was blocked */
  tool_event_id?: string
}

/** Behavioral memory of blocked normalized actions. */
export class BlockedActionMemory {
  private bySession = new Map<string, BlockedAction[]>()

  remember(action: BlockedAction): void {
    const list = this.bySession.get(action.session_id) ?? []
    list.push(action)
    this.bySession.set(action.session_id, list)
  }

  forSession(sessionId: string): BlockedAction[] {
    return [...(this.bySession.get(sessionId) ?? [])]
  }

  forAgent(sessionId: string, agentId: string): BlockedAction[] {
    return this.forSession(sessionId).filter(b => b.agent_id === agentId)
  }

  /** Blocks by ancestor agents (explicit parent chain via parentOf). */
  forAncestors(
    sessionId: string,
    agentId: string,
    parentOf: (id: string) => string | undefined,
  ): BlockedAction[] {
    const out: BlockedAction[] = []
    let cur: string | undefined = parentOf(agentId)
    const seen = new Set<string>()
    while (cur && !seen.has(cur)) {
      seen.add(cur)
      out.push(...this.forAgent(sessionId, cur))
      cur = parentOf(cur)
    }
    return out
  }
}

/** @deprecated Use BlockedActionMemory */
export const BlockedIntentMemory = BlockedActionMemory
/** @deprecated Use BlockedAction */
export type BlockedIntent = BlockedAction
