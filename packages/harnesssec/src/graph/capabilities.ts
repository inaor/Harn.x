import type { HarnessEvent } from '../events/schema.js'

function key(sessionId: string, agentId: string): string {
  return `${sessionId}\0${agentId}`
}

/**
 * CAPABILITY AVAILABLE vs CAPABILITY USED.
 * Available is only from capability.snapshot — never inferred from tool use.
 * A snapshot replaces prior available set (does not accumulate).
 * All state is scoped by (session_id, agent_id).
 */
export class CapabilityTracker {
  private available = new Map<string, string[]>()
  private used = new Map<string, Set<string>>()

  observe(event: HarnessEvent): void {
    const agentId = event.agent?.id
    if (!agentId) return
    const sessionId = event.session.id
    const k = key(sessionId, agentId)

    if (event.event_type === 'capability.snapshot' && event.capability?.available) {
      // Replace — current observed availability, not a union of history.
      this.available.set(k, [...event.capability.available].sort())
    }

    if (
      (event.event_type === 'tool.requested' || event.event_type === 'capability.used')
      && event.tool?.name
    ) {
      const set = this.used.get(k) ?? new Set()
      set.add(event.tool.name)
      this.used.set(k, set)
    }
  }

  /** Snapshot-declared available capabilities only (latest snapshot). */
  availableFor(sessionId: string, agentId: string): string[] {
    return [...(this.available.get(key(sessionId, agentId)) ?? [])]
  }

  /** Observed capability use (tool requests) — accumulates. */
  usedBy(sessionId: string, agentId: string): string[] {
    return [...(this.used.get(key(sessionId, agentId)) ?? [])].sort()
  }

  render(sessionId: string, agentId: string): string {
    const a = this.availableFor(sessionId, agentId)
    const u = this.usedBy(sessionId, agentId)
    return [
      `Agent ${agentId} (session ${sessionId})`,
      '  AVAILABLE (latest snapshot):',
      ...(a.length ? a.map(x => `    - ${x}`) : ['    (none observed)']),
      '  USED (observed history):',
      ...(u.length ? u.map(x => `    - ${x}`) : ['    (none)']),
    ].join('\n')
  }
}
