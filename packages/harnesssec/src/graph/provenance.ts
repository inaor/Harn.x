import type { HarnessEvent, TrustLevel } from '../events/schema.js'

export interface ContextRecord {
  id: string
  session_id: string
  agent_id?: string
  source_type: string
  source?: string
  trust: TrustLevel
  introduced_at: string
  event_id: string
}

/**
 * Context provenance — only where MessageSource / tool identity is known.
 * Not fake taint. Propagation is session+agent scoped "latest untrusted context".
 */
export class ContextProvenance {
  private byId = new Map<string, ContextRecord>()
  private latestUntrustedByAgent = new Map<string, string>()

  observe(event: HarnessEvent): void {
    if (event.event_type !== 'context.introduced' || !event.context) return
    const record: ContextRecord = {
      id: event.context.id,
      session_id: event.session.id,
      agent_id: event.agent?.id,
      source_type: event.context.source_type,
      source: event.context.source,
      trust: event.context.trust,
      introduced_at: event.timestamp,
      event_id: event.id,
    }
    this.byId.set(record.id, record)
    if (record.trust === 'untrusted' && record.agent_id) {
      this.latestUntrustedByAgent.set(`${record.session_id}:${record.agent_id}`, record.event_id)
    }
  }

  latestUntrusted(sessionId: string, agentId: string): string | undefined {
    return this.latestUntrustedByAgent.get(`${sessionId}:${agentId}`)
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
