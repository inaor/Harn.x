import { mkdirSync, readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { HarnessEvent } from '../events/schema.js'
import { CausalGraph } from '../graph/causal.js'
import { AgentLineage } from '../graph/lineage.js'
import { CapabilityTracker } from '../graph/capabilities.js'
import { TrustStore } from '../graph/trust.js'
import { ContextProvenance } from '../graph/provenance.js'

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

  private sessions = new Map<string, SessionRecord>()
  private lastToolByAgent = new Map<string, string>()
  private lastPolicyByAgent = new Map<string, string>()
  private storeDir: string

  constructor(storeDir: string) {
    this.storeDir = storeDir
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
    writeFileSync(join(this.storeDir, `${sessionId}.json`), JSON.stringify(session, null, 2))
  }

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

    if (event.event_type === 'tool.requested' && agentId) {
      const ctx = this.provenance.latestUntrusted(event.session.id, agentId)
      if (ctx) links.context_source = ctx
      const parent = this.lineage.parentOf(agentId)
      if (parent) links.parent_agent = parent
    }

    if (event.event_type === 'tool.completed' || event.event_type === 'tool.denied') {
      if (agentId) {
        const prior = this.lastToolByAgent.get(agentId)
        if (prior) links.result_of = prior
      }
    }

    if (event.event_type === 'policy.decision' && event.links?.policy_decision_for) {
      // keep
    } else if (event.event_type === 'policy.decision' && agentId) {
      const prior = this.lastToolByAgent.get(agentId)
      if (prior) links.policy_decision_for = prior
    }

    if (event.event_type === 'policy.aftermath' && agentId) {
      const prior = this.lastPolicyByAgent.get(agentId)
      if (prior) links.caused_by = prior
    }

    if (Object.keys(links).length > 0) event.links = links
  }

  private indexEvent(event: HarnessEvent, live: boolean): void {
    this.graph.add(event)

    if (event.agent?.id) {
      this.lineage.observe(event)
    }
    this.capabilities.observe(event)
    this.trust.observe(event)
    this.provenance.observe(event)

    if (event.event_type === 'tool.requested' && event.agent?.id) {
      this.lastToolByAgent.set(event.agent.id, event.id)
      this.maybeAftermath(event)
    }
    if (event.event_type === 'policy.decision' && event.agent?.id) {
      this.lastPolicyByAgent.set(event.agent.id, event.id)
    }

    if (live && event.event_type === 'tool.requested') {
      // aftermath detection happens on subsequent tool.requested via maybeAftermath
    }
  }

  private maybeAftermath(event: HarnessEvent): void {
    if (!event.agent?.id) return
    const lastPolicyId = this.lastPolicyByAgent.get(event.agent.id)
    if (!lastPolicyId) return
    const lastPolicy = this.graph.get(lastPolicyId)
    if (!lastPolicy || lastPolicy.policy?.decision !== 'block') return
    // Already recorded an aftermath for this policy? Check if this tool is after block.
    const already = this.sessions.get(event.session.id)?.events.some(
      e => e.event_type === 'policy.aftermath' && e.links?.caused_by === lastPolicyId,
    )
    if (already) return

    // Caller should record aftermath via PolicyEngine; mark for CLI visibility through link only.
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
}
