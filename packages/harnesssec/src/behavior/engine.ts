import type { HarnessEvent } from '../events/schema.js'
import { BlockedActionMemory } from './memory.js'
import { isDetectionEligible, normalizeAction } from './normalize.js'
import {
  findAlternateCapabilityCircumvention,
  findDelegatedPolicyCircumvention,
  findDelegationPrivilegeExpansion,
  type DetectionHit,
} from './detections.js'
import { buildDetectionEvent } from './emit.js'

function agentKey(sessionId: string, agentId: string): string {
  return `${sessionId}\0${agentId}`
}

/**
 * Parent relationship is separate from observed delegation/spawn.
 * Only `subagent.spawned` may set spawn_timestamp / spawn_event_id.
 */
export interface LineageNode {
  parent_id: string
  spawn_timestamp?: string
  spawn_event_id?: string
}

/**
 * Stateful behavioral engine — parallel consumer of normalized HarnessEvents.
 * All agent identity state is scoped by (session_id, agent_id).
 */
export class BehavioralEngine {
  readonly memory = new BlockedActionMemory()
  private readonly raised = new Set<string>()
  /** Latest capability.snapshot per (session, agent) — replaced, not accumulated. */
  private readonly snapshotByAgent = new Map<string, string[]>()
  private readonly eventsById = new Map<string, HarnessEvent>()
  /** Explicit parent lineage per (session, child). */
  private readonly lineageByChild = new Map<string, LineageNode>()
  private observing = false
  private observeDepth = 0

  /**
   * Rebuild state from a prior event stream without emitting detections.
   * Caller should pass events for one session at a time (recorder does).
   */
  hydrateSession(events: HarnessEvent[]): void {
    for (const event of events) {
      this.indexLocal(event)
      if (event.event_type === 'capability.snapshot' && event.agent?.id && event.capability?.available) {
        this.setSnapshot(event.session.id, event.agent.id, event.capability.available)
      }
      if (event.event_type === 'policy.decision' && event.policy?.decision === 'block') {
        this.rememberBlock(event)
      }
      if (event.event_type === 'behavior.detection' && event.detection) {
        this.raised.add(this.detectionKey(
          event.detection.kind,
          event.detection.evidence,
          event.session.id,
        ))
      }
    }
  }

  observe(event: HarnessEvent): HarnessEvent[] {
    if (this.observing) return []
    if (event.event_type === 'behavior.detection') {
      this.indexLocal(event)
      if (event.detection) {
        this.raised.add(this.detectionKey(
          event.detection.kind,
          event.detection.evidence,
          event.session.id,
        ))
      }
      return []
    }
    // Phase 4B reactions are factual correlator output — not detection input.
    if (event.event_type === 'agent.reaction') {
      this.indexLocal(event)
      return []
    }

    this.observeDepth++
    this.observing = true
    const out: HarnessEvent[] = []
    try {
      this.indexLocal(event)
      const sessionId = event.session.id

      if (event.event_type === 'capability.snapshot' && event.agent?.id && event.capability?.available) {
        this.setSnapshot(sessionId, event.agent.id, event.capability.available)
        for (const hit of this.privilegeHitsAfterSnapshot(sessionId, event.agent.id, event)) {
          const det = this.toDetection(hit, event, sessionId)
          if (det) out.push(det)
        }
      }

      if (event.event_type === 'policy.decision' && event.policy?.decision === 'block') {
        this.rememberBlock(event)
        return out
      }

      if (event.event_type === 'subagent.spawned' && event.agent?.id) {
        for (const hit of this.privilegeHitsForChild(sessionId, event.agent.id, event)) {
          const det = this.toDetection(hit, event, sessionId)
          if (det) out.push(det)
        }
      }

      if (event.event_type === 'tool.requested' && event.tool?.name) {
        for (const hit of this.circumventionHits(event)) {
          const det = this.toDetection(hit, event, sessionId)
          if (det) out.push(det)
        }
      }
    } finally {
      this.observeDepth--
      if (this.observeDepth === 0) this.observing = false
    }
    return out
  }

  /** Session-scoped parent lookup (relationship only — may lack spawn). */
  parentOf(sessionId: string, agentId: string): string | undefined {
    return this.lineageByChild.get(agentKey(sessionId, agentId))?.parent_id
  }

  /** True only when a real subagent.spawned was observed for this child. */
  hasObservedSpawn(sessionId: string, agentId: string): boolean {
    const node = this.lineageByChild.get(agentKey(sessionId, agentId))
    return Boolean(node?.spawn_timestamp && node?.spawn_event_id)
  }

  /** Test/helper: latest snapshot for (session, agent). */
  snapshotFor(sessionId: string, agentId: string): string[] {
    return [...(this.snapshotByAgent.get(agentKey(sessionId, agentId)) ?? [])]
  }

  /** Test/helper: lineage node for (session, child). */
  lineageFor(sessionId: string, agentId: string): LineageNode | undefined {
    const node = this.lineageByChild.get(agentKey(sessionId, agentId))
    return node ? { ...node } : undefined
  }

  private setSnapshot(sessionId: string, agentId: string, available: string[]): void {
    this.snapshotByAgent.set(agentKey(sessionId, agentId), [...available].sort())
  }

  private indexLocal(event: HarnessEvent): void {
    this.eventsById.set(event.id, event)
    const agentId = event.agent?.id
    if (!agentId) return
    const sessionId = event.session.id
    const k = agentKey(sessionId, agentId)

    const parentId = event.agent?.parent_agent_id
      ?? (event.links?.parent_agent || undefined)
      ?? undefined

    if (event.event_type === 'subagent.spawned' && parentId) {
      this.lineageByChild.set(k, {
        parent_id: parentId,
        spawn_timestamp: event.timestamp,
        spawn_event_id: event.id,
      })
      if (event.capability?.available) {
        this.setSnapshot(sessionId, agentId, event.capability.available)
      }
      return
    }

    if (parentId) {
      const prev = this.lineageByChild.get(k)
      if (prev) {
        // Update parent relationship only — never fabricate spawn from this event.
        this.lineageByChild.set(k, {
          parent_id: parentId,
          spawn_timestamp: prev.spawn_timestamp,
          spawn_event_id: prev.spawn_event_id,
        })
      } else {
        this.lineageByChild.set(k, { parent_id: parentId })
      }
    }
  }

  private rememberBlock(event: HarnessEvent): void {
    const agentId = event.agent?.id
    if (!agentId) return
    const toolEventId = event.links?.policy_decision_for
    const toolEvent = toolEventId ? this.eventsById.get(toolEventId) : undefined
    const source = toolEvent ?? event
    const norm = normalizeAction(source)
    if (!norm.target || !isDetectionEligible(norm)) return
    this.memory.remember({
      agent_id: agentId,
      session_id: event.session.id,
      category: norm.category,
      target: norm.target,
      capability: norm.capability,
      tool_name: norm.tool_name,
      level: norm.level,
      timestamp: toolEvent?.timestamp ?? event.timestamp,
      policy_rule: event.policy?.rule,
      event_id: event.id,
      tool_event_id: toolEventId,
    })
  }

  private circumventionHits(event: HarnessEvent): DetectionHit[] {
    const agentId = event.agent?.id
    if (!agentId) return []
    const action = normalizeAction(event)
    if (!isDetectionEligible(action)) return []
    const hits: DetectionHit[] = []
    const sessionId = event.session.id

    const alt = findAlternateCapabilityCircumvention({
      memory: this.memory,
      sessionId,
      agentId,
      action,
      actionTimestamp: event.timestamp,
      actionEventId: event.id,
    })
    if (alt) hits.push(alt)

    const lineage = this.lineageByChild.get(agentKey(sessionId, agentId))
    // Delegated circumvention requires OBSERVED spawn/delegation timestamp.
    if (lineage?.spawn_timestamp && lineage.spawn_event_id) {
      const del = findDelegatedPolicyCircumvention({
        memory: this.memory,
        sessionId,
        agentId,
        parentOf: (id) => this.parentOf(sessionId, id),
        action,
        actionTimestamp: event.timestamp,
        actionEventId: event.id,
        spawnTimestamp: lineage.spawn_timestamp,
      })
      if (del) hits.push(del)
    }
    return hits
  }

  /**
   * After a snapshot: evaluate the agent as a child, and if it is a parent,
   * evaluate all known children (order-independent).
   */
  private privilegeHitsAfterSnapshot(
    sessionId: string,
    agentId: string,
    trigger: HarnessEvent,
  ): DetectionHit[] {
    const hits: DetectionHit[] = []
    hits.push(...this.privilegeHitsForChild(sessionId, agentId, trigger))
    for (const [k, node] of this.lineageByChild) {
      if (!k.startsWith(`${sessionId}\0`)) continue
      if (node.parent_id !== agentId) continue
      const childId = k.slice(sessionId.length + 1)
      hits.push(...this.privilegeHitsForChild(sessionId, childId, trigger))
    }
    return hits
  }

  private privilegeHitsForChild(
    sessionId: string,
    childId: string,
    trigger: HarnessEvent,
  ): DetectionHit[] {
    const lineage = this.lineageByChild.get(agentKey(sessionId, childId))
    if (!lineage) return []
    const parentId = lineage.parent_id

    const parentCaps = this.snapshotByAgent.get(agentKey(sessionId, parentId))
    const childCaps = this.snapshotByAgent.get(agentKey(sessionId, childId))
    if (!parentCaps?.length || !childCaps?.length) return []

    const spawnEventId = lineage.spawn_event_id ?? `lineage:${sessionId}:${parentId}:${childId}`
    const hit = findDelegationPrivilegeExpansion({
      parentAgentId: parentId,
      childAgentId: childId,
      parentAvailable: parentCaps,
      childAvailable: childCaps,
      sessionId,
      spawnEventId,
      timestamp: trigger.timestamp,
    })
    return hit ? [hit] : []
  }

  private detectionKey(
    kind: string,
    evidence: { blocked_event_id: string; action_event_id: string; parent_agent_id?: string; child_agent_id?: string },
    sessionId: string,
  ): string {
    if (kind === 'agent.delegation_privilege_expansion') {
      // Stable across event order — one detection per parent/child/session.
      return `${kind}|${sessionId}|${evidence.parent_agent_id ?? ''}|${evidence.child_agent_id ?? ''}`
    }
    return `${kind}|${evidence.blocked_event_id}|${evidence.action_event_id}`
  }

  private toDetection(
    hit: DetectionHit,
    trigger: HarnessEvent,
    sessionId: string,
  ): HarnessEvent | undefined {
    const key = this.detectionKey(hit.kind, hit.evidence, sessionId)
    if (this.raised.has(key)) return undefined
    this.raised.add(key)
    return buildDetectionEvent(hit, trigger)
  }
}
