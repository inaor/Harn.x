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

  /**
   * Persist a redacted clone only. Never mutate in-memory session/events.
   * Redaction happens here — not in record() — so policy/detection see raw telemetry.
   */
  private persist(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (!session) return
    // redactEvent deep-clones; session / events in memory are untouched.
    const safe = redactEvent(session as unknown as Record<string, unknown>)
    writeFileSync(join(this.storeDir, `${sessionId}.json`), JSON.stringify(safe, null, 2))
  }

  /**
   * Store and return the original/raw event for policy, detection, and correlation.
   * Do not redact here. Disk writes go through persist() only.
   */
  record(event: HarnessEvent): HarnessEvent {
    let session = this.sessions.get(event.session.id)
    if (!session) {
      session = {
        session_id: event.session.id,
        started_at: event.timestamp,
        events: [],
      }
      this.sessions.set(event.session.id, session)
    }

    if (event.event_type === 'objective.captured' && event.objective) {
      session.objective = event.objective
    }
    if (event.event_type === 'session.ended') {
      session.ended_at = event.timestamp
    }

    this.enrichLinks(event)
    session.events.push(event)
    this.indexEvent(event, true)
    this.persist(event.session.id)
    return event
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
      // No association when turn is unknown — never sticky latestUntrusted().
      const candidate = this.provenance.candidateUntrustedForStep(event.session.id, agentId, turn)
      if (candidate) {
        links.candidate_context_source = candidate
        links.correlated_with = candidate
      }
      const parent = this.lineage.parentOf(agentId)
      if (parent) links.parent_agent = parent
    }

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
