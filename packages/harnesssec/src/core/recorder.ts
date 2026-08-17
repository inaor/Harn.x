import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  readdirSync,
  existsSync,
  openSync,
  closeSync,
  unlinkSync,
} from 'node:fs'
import { join } from 'node:path'
import type { HarnessEvent } from '../events/schema.js'
import { CausalGraph } from '../graph/causal.js'
import { AgentLineage } from '../graph/lineage.js'
import { CapabilityTracker } from '../graph/capabilities.js'
import { TrustStore } from '../graph/trust.js'
import { ContextProvenance } from '../graph/provenance.js'
import { BehavioralEngine } from '../behavior/engine.js'
import {
  backfillSessionReactions,
  shouldCorrelateAfter,
} from '../behavior/reaction.js'
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
  readonly behavior: BehavioralEngine

  private sessions = new Map<string, SessionRecord>()
  private lastToolByAgent = new Map<string, string>()
  private lastPolicyByAgent = new Map<string, string>()
  private storeDir: string

  constructor(storeDir: string, mcpTrust?: McpTrustRegistry) {
    this.storeDir = storeDir
    this.mcpTrust = mcpTrust ?? new McpTrustRegistry(DEFAULT_MCP_TRUST)
    mkdirSync(storeDir, { recursive: true })
    this.behavior = new BehavioralEngine()
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
        this.behavior.hydrateSession(raw.events)
      } catch {
        // skip corrupt
      }
    }
  }

  /**
   * Exclusive lock for session JSON — Cursor may fire parallel preToolUse processes
   * against the same conversation_id; last-write-wins without merge loses events
   * (Proof B2: Grep .env tool_use in transcript with no Harn.x tool.requested).
   */
  private withSessionLock(sessionId: string, fn: () => void): void {
    const lockPath = join(this.storeDir, `${sessionId}.json.lock`)
    const deadline = Date.now() + 5000
    while (true) {
      try {
        const fd = openSync(lockPath, 'wx')
        try {
          fn()
        } finally {
          closeSync(fd)
          try {
            unlinkSync(lockPath)
          } catch {
            // lock file may already be gone
          }
        }
        return
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code
        if (code !== 'EEXIST' || Date.now() >= deadline) throw err
        // Busy-wait briefly; parallel hook processes are short-lived.
        const waitUntil = Date.now() + 15
        while (Date.now() < waitUntil) {
          /* spin */
        }
      }
    }
  }

  /**
   * Persist a redacted clone only. Never mutate in-memory session/events with
   * redacted disk clones — policy/detection must keep seeing raw telemetry.
   * Merges with on-disk events by id so concurrent hook processes do not drop
   * sibling tool.requested rows (Proof B2 Grep telemetry gap).
   */
  private persist(sessionId: string): void {
    const session = this.sessions.get(sessionId)
    if (!session) return
    this.withSessionLock(sessionId, () => {
      const path = join(this.storeDir, `${sessionId}.json`)
      const byId = new Map<string, HarnessEvent>()
      let diskStarted = session.started_at
      let diskEnded = session.ended_at
      let diskObjective = session.objective
      if (existsSync(path)) {
        try {
          const disk = JSON.parse(readFileSync(path, 'utf8')) as SessionRecord
          for (const e of disk.events ?? []) {
            if (e?.id) byId.set(e.id, e)
          }
          if (disk.started_at && disk.started_at < diskStarted) diskStarted = disk.started_at
          if (disk.ended_at) diskEnded = disk.ended_at
          if (disk.objective && !diskObjective) diskObjective = disk.objective
        } catch {
          // corrupt disk — write memory view
        }
      }
      // Memory wins on id collision (raw in-process events over prior redacted disk).
      for (const e of session.events) {
        if (e?.id) byId.set(e.id, e)
      }
      const mergedEvents = [...byId.values()].sort((a, b) => {
        const t = String(a.timestamp).localeCompare(String(b.timestamp))
        return t !== 0 ? t : String(a.id).localeCompare(String(b.id))
      })
      const toWrite: SessionRecord = {
        session_id: session.session_id,
        started_at: diskStarted,
        ended_at: diskEnded,
        objective: diskObjective,
        events: mergedEvents,
      }
      const safe = redactEvent(toWrite as unknown as Record<string, unknown>)
      writeFileSync(path, JSON.stringify(safe, null, 2))
    })
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
    // Parallel consumer: behavior does not depend on persistence.
    const detections = this.behavior.observe(event)
    this.persist(event.session.id)
    for (const det of detections) {
      // record() will observe behavior.detection → engine returns [] (no recursion).
      this.record(det)
    }
    // Phase 4B: factual AGENT_REACTION backfill (separate from behavior.detection).
    if (event.event_type !== 'agent.reaction' && shouldCorrelateAfter(event)) {
      const fresh = this.getSession(event.session.id)?.events ?? session.events
      const reactions = backfillSessionReactions(fresh)
      for (const rx of reactions) {
        this.record(rx)
      }
    }
    return event
  }

  /**
   * Replay helper: persist missing agent.reaction events for a session.
   * Safe to call multiple times (idempotent per block id).
   */
  backfillReactions(sessionId: string): HarnessEvent[] {
    const session = this.getSession(sessionId)
    if (!session) return []
    const created = backfillSessionReactions(session.events)
    for (const rx of created) {
      this.record(rx)
    }
    return created
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
