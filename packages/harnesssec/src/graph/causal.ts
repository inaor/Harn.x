import type { HarnessEvent } from '../events/schema.js'

export interface CausalEdge {
  from: string
  to: string
  relation: string
}

/** Causal graph over harness events — not a flat log. */
export class CausalGraph {
  private events = new Map<string, HarnessEvent>()
  private edges: CausalEdge[] = []

  add(event: HarnessEvent): void {
    this.events.set(event.id, event)
    const links = event.links ?? {}
    for (const [relation, target] of Object.entries(links)) {
      if (typeof target === 'string' && target) {
        this.edges.push({ from: target, to: event.id, relation })
      }
    }
  }

  get(id: string): HarnessEvent | undefined {
    return this.events.get(id)
  }

  all(): HarnessEvent[] {
    return [...this.events.values()].sort((a, b) => a.timestamp.localeCompare(b.timestamp))
  }

  forSession(sessionId: string): HarnessEvent[] {
    return this.all().filter(e => e.session.id === sessionId)
  }

  edgesForSession(sessionId: string): CausalEdge[] {
    const ids = new Set(this.forSession(sessionId).map(e => e.id))
    return this.edges.filter(e => ids.has(e.from) || ids.has(e.to))
  }

  /** Walk backward from a suspicious event to reconstruct why. */
  why(eventId: string): HarnessEvent[] {
    const chain: HarnessEvent[] = []
    const seen = new Set<string>()
    const queue = [eventId]
    while (queue.length) {
      const id = queue.shift()!
      if (seen.has(id)) continue
      seen.add(id)
      const event = this.events.get(id)
      if (!event) continue
      chain.push(event)
      const links = event.links ?? {}
      for (const key of ['caused_by', 'parent_event', 'context_source', 'candidate_context_source', 'correlated_with', 'result_of', 'policy_decision_for', 'delegated_by', 'attempted_after', 'equivalent_to', 'blocked_by'] as const) {
        const ref = links[key]
        if (ref) queue.push(ref)
      }
    }
    return chain.sort((a, b) => a.timestamp.localeCompare(b.timestamp))
  }

  render(sessionId: string): string {
    const events = this.forSession(sessionId)
    const lines: string[] = [`SESSION GRAPH: ${sessionId}`, '']
    for (const e of events) {
      const linkBits = e.links
        ? Object.entries(e.links).map(([k, v]) => `${k}=${v}`).join(' ')
        : ''
      lines.push(`${e.timestamp}  ${e.event_type}  [${e.id}]`)
      if (e.tool?.name) lines.push(`  tool: ${e.tool.name}`)
      if (e.action?.target) lines.push(`  target: ${e.action.target}`)
      if (e.context) lines.push(`  context: ${e.context.source_type} trust=${e.context.trust}`)
      if (e.policy) lines.push(`  policy: ${e.policy.decision} ${e.policy.rule ?? ''}`)
      if (e.detection) lines.push(`  detection: ${e.detection.kind} ${e.detection.severity}`)
      if (linkBits) lines.push(`  links: ${linkBits}`)
      lines.push('')
    }
    return lines.join('\n')
  }
}
