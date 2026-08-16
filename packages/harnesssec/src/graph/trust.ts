import type { HarnessEvent, TrustLevel } from '../events/schema.js'

export interface TrustEdge {
  from: string
  to: string
  relation: string
  trust: TrustLevel
}

export class TrustStore {
  private edges: TrustEdge[] = []

  observe(event: HarnessEvent): void {
    const agent = event.agent?.id
    if (!agent) return

    if (event.context) {
      this.edges.push({
        from: agent,
        to: `context:${event.context.id}`,
        relation: 'consumed',
        trust: event.context.trust,
      })
    }
    if (event.tool?.name) {
      this.edges.push({
        from: agent,
        to: `tool:${event.tool.name}`,
        relation: 'uses',
        trust: event.tool.name.startsWith('mcp__') ? 'untrusted' : 'unknown',
      })
    }
    if (event.event_type === 'subagent.spawned' && event.agent?.parent_agent_id) {
      this.edges.push({
        from: event.agent.parent_agent_id,
        to: agent,
        relation: 'delegated_to',
        trust: 'unknown',
      })
    }
  }

  forAgent(agentId: string): TrustEdge[] {
    return this.edges.filter(e => e.from === agentId || e.to === agentId)
  }

  render(agentId: string): string {
    const edges = this.forAgent(agentId)
    if (!edges.length) return `(no trust edges for ${agentId})`
    return edges.map(e => `${e.from} --${e.relation}[${e.trust}]--> ${e.to}`).join('\n')
  }
}
