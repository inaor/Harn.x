import type { HarnessEvent } from '../events/schema.js'

export interface AgentNode {
  agent_id: string
  parent_agent_id?: string | null
  /** OBSERVED from links.delegated_by when present. */
  delegated_by?: string
  session_id: string
  created_at: string
  ended_at?: string
  objective?: string
  tools_seen: Set<string>
  /** OBSERVED capability.snapshot at spawn/start — never fabricated. */
  capabilities_at_spawn?: string[]
}

export class AgentLineage {
  private agents = new Map<string, AgentNode>()

  observe(event: HarnessEvent): void {
    if (!event.agent?.id) return
    const id = event.agent.id
    let node = this.agents.get(id)
    if (!node) {
      node = {
        agent_id: id,
        parent_agent_id: event.agent.parent_agent_id ?? null,
        session_id: event.session.id,
        created_at: event.timestamp,
        tools_seen: new Set(),
      }
      this.agents.set(id, node)
    }
    if (event.event_type === 'subagent.spawned' && event.agent.parent_agent_id) {
      node.parent_agent_id = event.agent.parent_agent_id
      if (event.links?.delegated_by) node.delegated_by = event.links.delegated_by
      if (event.capability?.available) {
        node.capabilities_at_spawn = [...event.capability.available]
      }
    }
    if (event.event_type === 'capability.snapshot' && event.capability?.available && !node.capabilities_at_spawn) {
      node.capabilities_at_spawn = [...event.capability.available]
    }
    if (event.event_type === 'agent.ended' || event.event_type === 'subagent.ended') {
      node.ended_at = event.timestamp
    }
    if (event.objective?.description) node.objective = event.objective.description
    if (event.tool?.name) node.tools_seen.add(event.tool.name)
  }

  parentOf(agentId: string): string | undefined {
    return this.agents.get(agentId)?.parent_agent_id ?? undefined
  }

  get(agentId: string): AgentNode | undefined {
    return this.agents.get(agentId)
  }

  tree(sessionId: string): string {
    const nodes = [...this.agents.values()].filter(a => a.session_id === sessionId)
    const roots = nodes.filter(n => !n.parent_agent_id)
    const children = (id: string) => nodes.filter(n => n.parent_agent_id === id)
    const render = (n: AgentNode, depth: number): string[] => {
      const pad = '  '.repeat(depth)
      const lines = [`${pad}${n.agent_id}${n.objective ? ` — ${n.objective}` : ''}`]
      for (const c of children(n.agent_id)) lines.push(...render(c, depth + 1))
      return lines
    }
    if (roots.length === 0 && nodes.length) {
      return nodes.map(n => `${n.agent_id} (parent=${n.parent_agent_id ?? 'none'})`).join('\n')
    }
    return roots.flatMap(r => render(r, 0)).join('\n') || '(no agents)'
  }
}
