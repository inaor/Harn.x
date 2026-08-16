import { mkdirSync, readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { HarnessEvent } from '../events/schema.js'
import { CausalGraph } from '../graph/causal.js'
import { AgentLineage } from '../graph/lineage.js'
import { CapabilityTracker } from '../graph/capabilities.js'
import { TrustStore } from '../graph/trust.js'
import { ContextProvenance } from '../graph/provenance.js'
import { McpTrustRegistry, DEFAULT_MCP_TRUST } from './mcp-trust.js'
import { redactEvent } from './redact.js'

export interface SessionRecord {
  session_id: string
  started_at: string
  ended_at?: string
  objective?: { id: string; description: string }
  events: HarnessEvent[]
}

export class FlightRecorder {
  readonly graph = new CausalGraph()
  readonly lineage = new AgentLineage()
  readonly capabilities = new CapabilityTracker()
  readonly trust = new TrustStore()
  readonly provenance = new ContextProvenance()
  readonly mcpTrust: McpTrustRegistry

  private sessions = new Map<string, SessionRecord>()
  private lastToolByAgent = new Map<string, string>()
  private lastPolicyByAgent = new Map<string, string>()
  private storeDir: string

  constructor(storeDir: string, mcpTrust?: McpTrustRegistry) {
    this.storeDir = storeDir
    this.mcpTrust = mcpTrust ?? new McpTrustRegistry(DEFAULT_MCP_TRUST)
    mkdirSync(storeDir, { recursive: true })
    this.loadExisting()
  }

  private loadExisting(): void {
    if (!existsSync(this.storeDir)) return
    for (const name of readdirSync(this.storeDir)) {
      if (!name.endsWith('.json')) continue
      try {
        const raw = JSON.parse(readFileSync(join(this.storeDir, name), 'utf8')) as SessionRecord
        this.sessions.set(raw.session_id, raw)
        for (const event of raw.events) this.indexEvent(event, false)
      } catch {
        // skip corrupt
      }
    }
  }

  private persist(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (!session) return
    const safe = redactEvent(session as unknown as Record<string, unknown>)
    writeFileSync(join(this.storeDir, `${sessionId}.json`), JSON.stringify(safe, null, 2))
  }

  record(event: HarnessEvent): HarnessEvent {
    // Redact before any in-memory enrichment is persisted; keep working copy redacted too.
    const safeEvent = redactEvent(event as unknown as Record<string, unknown>) as unknown as HarnessEvent

    let session = this.sessions.get(safeEvent.session.id)
    if (!session) {
      session = {
        session_id: safeEvent.session.id,
        started_at: safeEvent.timestamp,
        events: [],
      }
      this.sessions.set(safeEvent.session.id, session)
    }

    if (safeEvent.event_type === 'objective.captured' && safeEvent.objective) {
      session.objective = safeEvent.objective
    }
    if (safeEvent.event_type === 'session.ended') {
      session.ended_at = safeEvent.timestamp
    }

    this.enrichLinks(safeEvent)
    session.events.push(safeEvent)
    this.indexEvent(safeEvent, true)
    this.persist(safeEvent.session.id)
    return safeEvent
  }

  private enrichLinks(event: HarnessEvent): void {
    const links = { ...(event.links ?? {}) }
    const agentId = event.agent?.id
    const turn = event.turn
      ?? event.context?.turn
      ?? (event.action?.arguments && typeof (event.action.arguments as any).turn === 'number'
        ? (event.action.arguments as any).turn as number
        : undefined)

    if (event.event_type === 'tool.requested' && agentId) {
      const candidate = this.provenance.candidateUntrustedForStep(event.session.id, agentId, turn)
      if (candidate) {
        links.candidate_context_source = candidate
        links.correlated_with = candidate
        // Do NOT set caused_by or context_source from temporal co-occurrence.
      }
      const parent = this.lineage.parentOf(agentId)
      if (parent) links.parent_agent = parent
    }

    // Defensible causality: deny/complete is the result of the prior request from this agent.
    if (event.event_type === 'tool.completed' || event.event_type === 'tool.denied') {
      if (agentId) {
        const prior = this.lastToolByAgent.get(agentId)
        if (prior) links.result_of = prior
      }
    }

    if (event.event_type === 'policy.decision' && !links.policy_decision_for && agentId) {
      const prior = this.lastToolByAgent.get(agentId)
      if (prior) links.policy_decision_for = prior
    }

    // Aftermath is correlated with prior block; caused_by only if we have explicit policy id.
    if (event.event_type === 'policy.aftermath' && agentId) {
      const prior = this.lastPolicyByAgent.get(agentId)
      if (prior && !links.caused_by) {
        links.correlated_with = prior
      }
    }

    if (Object.keys(links).length > 0) event.links = links
  }

  private indexEvent(event: HarnessEvent, _live: boolean): void {
    this.graph.add(event)

    if (event.agent?.id) {
      this.lineage.observe(event)
    }
    this.capabilities.observe(event)
    this.trust.observe(event)
    this.provenance.observe(event)

    if (event.mcp?.server) {
      this.mcpTrust.observe(event.mcp.server)
    }

    if (event.event_type === 'tool.requested' && event.agent?.id) {
      this.lastToolByAgent.set(event.agent.id, event.id)
    }
    if (event.event_type === 'policy.decision' && event.agent?.id) {
      this.lastPolicyByAgent.set(event.agent.id, event.id)
    }
  }

  listSessions(): SessionRecord[] {
    return [...this.sessions.values()].sort((a, b) => a.started_at.localeCompare(b.started_at))
  }

  getSession(sessionId: string): SessionRecord | undefined {
    return this.sessions.get(sessionId)
  }

  getEvent(eventId: string): HarnessEvent | undefined {
    return this.graph.get(eventId)
  }

  getStoreDir(): string {
    return this.storeDir
  }
}
