import type { HarnessEvent, TrustLevel } from '../events/schema.js'

export interface ContextRecord {
  id: string
  session_id: string
  agent_id?: string
  /** Turn that introduced or last associated this context. */
  turn?: number
  step?: number
  source_type: string
  source?: string
  trust: TrustLevel
  introduced_at: string
  event_id: string
}

/**
 * Context provenance scoped to turn/step — not sticky for the whole session.
 *
 * Association rule (defensible, not fake taint):
 * - A context is active for tool requests in the same (session, agent, turn)
 *   where it was introduced, until the next turn starts.
 * - Cross-turn "influence" is correlation only, not caused_by.
 */
export class ContextProvenance {
  private byId = new Map<string, ContextRecord>()
  /** session:agent:turn → untrusted context event ids active in that turn */
  private byTurn = new Map<string, string[]>()
  private currentTurn = new Map<string, { turn: number; step: number }>()

  observe(event: HarnessEvent): void {
    const agentId = event.agent?.id
    const sessionId = event.session.id

    if (event.event_type === 'agent.step.admitted' && agentId) {
      const turn = event.action?.arguments && typeof (event.action.arguments as any).turn === 'number'
        ? (event.action.arguments as any).turn as number
        : undefined
      const step = event.action?.arguments && typeof (event.action.arguments as any).step === 'number'
        ? (event.action.arguments as any).step as number
        : undefined
      if (turn !== undefined) {
        this.currentTurn.set(`${sessionId}:${agentId}`, { turn, step: step ?? 0 })
      }
    }

    if (event.event_type !== 'context.introduced' || !event.context) return

    const pos = agentId ? this.currentTurn.get(`${sessionId}:${agentId}`) : undefined
    const turn = event.context.turn ?? pos?.turn
    const step = event.context.step ?? pos?.step

    const record: ContextRecord = {
      id: event.context.id,
      session_id: sessionId,
      agent_id: agentId,
      turn,
      step,
      source_type: event.context.source_type,
      source: event.context.source,
      trust: event.context.trust,
      introduced_at: event.timestamp,
      event_id: event.id,
    }
    this.byId.set(record.id, record)

    if (record.trust === 'untrusted' && agentId && turn !== undefined) {
      const key = `${sessionId}:${agentId}:${turn}`
      const list = this.byTurn.get(key) ?? []
      list.push(record.event_id)
      this.byTurn.set(key, list)
    }
  }

  /** Untrusted context introduced in the same turn (defensible association). */
  untrustedInTurn(sessionId: string, agentId: string, turn: number): string[] {
    return this.byTurn.get(`${sessionId}:${agentId}:${turn}`) ?? []
  }

  /**
   * Candidate context for a tool request in a given turn.
   * Returns same-turn untrusted contexts only.
   */
  candidateUntrustedForStep(
    sessionId: string,
    agentId: string,
    turn: number | undefined,
  ): string | undefined {
    if (turn === undefined) return undefined
    const list = this.untrustedInTurn(sessionId, agentId, turn)
    return list.length ? list[list.length - 1] : undefined
  }

  /** @deprecated sticky session lookup — do not use for policy. */
  latestUntrusted(sessionId: string, agentId: string): string | undefined {
    const prefix = `${sessionId}:${agentId}:`
    let best: string | undefined
    let bestTurn = -1
    for (const [key, ids] of this.byTurn) {
      if (!key.startsWith(prefix) || !ids.length) continue
      const turn = Number(key.slice(prefix.length))
      if (turn >= bestTurn) {
        bestTurn = turn
        best = ids[ids.length - 1]
      }
    }
    return best
  }

  get(contextId: string): ContextRecord | undefined {
    return this.byId.get(contextId)
  }

  forSession(sessionId: string): ContextRecord[] {
    return [...this.byId.values()]
      .filter(c => c.session_id === sessionId)
      .sort((a, b) => a.introduced_at.localeCompare(b.introduced_at))
  }
}
