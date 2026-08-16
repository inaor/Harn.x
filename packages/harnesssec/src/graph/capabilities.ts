import type { HarnessEvent } from '../events/schema.js'

/**
 * CAPABILITY AVAILABLE vs CAPABILITY USED.
 * Available is only from capability.snapshot — never inferred from tool use.
 */
export class CapabilityTracker {
  private available = new Map<string, Set<string>>()
  private used = new Map<string, Set<string>>()

  observe(event: HarnessEvent): void {
    const agentId = event.agent?.id
    if (!agentId) return

    if (event.event_type === 'capability.snapshot' && event.capability?.available) {
      const set = this.available.get(agentId) ?? new Set()
      for (const name of event.capability.available) set.add(name)
      this.available.set(agentId, set)
    }

    if (
      (event.event_type === 'tool.requested' || event.event_type === 'capability.used')
      && event.tool?.name
    ) {
      const set = this.used.get(agentId) ?? new Set()
      set.add(event.tool.name)
      this.used.set(agentId, set)
      // Do NOT add to available — use ≠ availability.
    }
  }

  /** Snapshot-declared available capabilities only. */
  availableFor(agentId: string): string[] {
    return [...(this.available.get(agentId) ?? [])].sort()
  }

  /** Observed capability use (tool requests). */
  usedBy(agentId: string): string[] {
    return [...(this.used.get(agentId) ?? [])].sort()
  }

  render(agentId: string): string {
    const a = this.availableFor(agentId)
    const u = this.usedBy(agentId)
    return [
      `Agent ${agentId}`,
      '  AVAILABLE (snapshot):',
      ...(a.length ? a.map(x => `    - ${x}`) : ['    (none observed)']),
      '  USED (observed):',
      ...(u.length ? u.map(x => `    - ${x}`) : ['    (none)']),
    ].join('\n')
  }
}
