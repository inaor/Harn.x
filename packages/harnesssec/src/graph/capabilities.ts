import type { HarnessEvent } from '../events/schema.js'

/** CAPABILITY AVAILABLE vs CAPABILITY USED */
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

      // First sighting also expands available if no snapshot yet
      const avail = this.available.get(agentId) ?? new Set()
      avail.add(event.tool.name)
      this.available.set(agentId, avail)
    }
  }

  availableFor(agentId: string): string[] {
    return [...(this.available.get(agentId) ?? [])].sort()
  }

  usedBy(agentId: string): string[] {
    return [...(this.used.get(agentId) ?? [])].sort()
  }

  render(agentId: string): string {
    const a = this.availableFor(agentId)
    const u = this.usedBy(agentId)
    return [
      `Agent ${agentId}`,
      '  AVAILABLE:',
      ...a.map(x => `    - ${x}`),
      '  USED:',
      ...u.map(x => `    - ${x}`),
    ].join('\n')
  }
}
