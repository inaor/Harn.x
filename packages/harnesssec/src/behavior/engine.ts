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

/**
 * Stateful behavioral engine — parallel consumer of normalized HarnessEvents.
 * Does not depend on persistence. Vendor-neutral: never branches on harness.name.
 */
export class BehavioralEngine {
  readonly memory = new BlockedActionMemory()
  private readonly raised = new Set<string>()
  private readonly snapshotObserved = new Set<string>()
  private readonly snapshotByAgent = new Map<string, string[]>()
  /** Local event index for resolving policy_decision_for — not a persistence store. */
  private readonly eventsById = new Map<string, HarnessEvent>()
  /** Explicit parent links observed on events. */
  private readonly parentByAgent = new Map<string, string>()
  /** Re-entrancy guard: never process while emitting / nested observe of detections. */
  private observing = false
  private observeDepth = 0

  /**
   * Rebuild blocked-action memory from a prior event stream without emitting detections.
   */
  hydrateSession(events: HarnessEvent[]): void {
    for (const event of events) {
      this.indexLocal(event)
      if (event.event_type === 'capability.snapshot' && event.agent?.id && event.capability?.available) {
        this.snapshotObserved.add(event.agent.id)
        this.snapshotByAgent.set(event.agent.id, [...event.capability.available].sort())
      }
      if (event.event_type === 'policy.decision' && event.policy?.decision === 'block') {
        this.rememberBlock(event)
      }
      if (event.event_type === 'behavior.detection' && event.detection) {
        const key = `${event.detection.kind}|${event.detection.evidence.blocked_event_id}|${event.detection.evidence.action_event_id}`
        this.raised.add(key)
      }
    }
  }

  /**
   * Consume one normalized event. Returns zero or more behavior.detection events
   * for the caller to persist/fan-out. Never recursively observes those detections.
   */
  observe(event: HarnessEvent): HarnessEvent[] {
    if (this.observing) return []
    if (event.event_type === 'behavior.detection') {
      this.indexLocal(event)
      if (event.detection) {
        const key = `${event.detection.kind}|${event.detection.evidence.blocked_event_id}|${event.detection.evidence.action_event_id}`
        this.raised.add(key)
      }
      return []
    }

    this.observeDepth++
    this.observing = true
    const out: HarnessEvent[] = []
    try {
      this.indexLocal(event)

      if (event.event_type === 'capability.snapshot' && event.agent?.id && event.capability?.available) {
        this.snapshotObserved.add(event.agent.id)
        this.snapshotByAgent.set(event.agent.id, [...event.capability.available].sort())
      }

      if (event.event_type === 'policy.decision' && event.policy?.decision === 'block') {
        this.rememberBlock(event)
        return out
      }

      if (event.event_type === 'subagent.spawned' && event.agent?.id) {
        for (const hit of this.privilegeHits(event)) {
          const det = this.toDetection(hit, event)
          if (det) out.push(det)
        }
      }

      if (event.event_type === 'tool.requested' && event.tool?.name) {
        for (const hit of this.circumventionHits(event)) {
          const det = this.toDetection(hit, event)
          if (det) out.push(det)
        }
      }
    } finally {
      this.observeDepth--
      if (this.observeDepth === 0) this.observing = false
    }
    return out
  }

  parentOf(agentId: string): string | undefined {
    return this.parentByAgent.get(agentId)
  }

  private indexLocal(event: HarnessEvent): void {
    this.eventsById.set(event.id, event)
    if (event.agent?.id && event.agent.parent_agent_id) {
      this.parentByAgent.set(event.agent.id, event.agent.parent_agent_id)
    }
    if (event.event_type === 'subagent.spawned' && event.agent?.id && event.agent.parent_agent_id) {
      this.parentByAgent.set(event.agent.id, event.agent.parent_agent_id)
    }
    if (event.links?.parent_agent && event.agent?.id) {
      this.parentByAgent.set(event.agent.id, event.links.parent_agent)
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

    const alt = findAlternateCapabilityCircumvention({
      memory: this.memory,
      sessionId: event.session.id,
      agentId,
      action,
      actionTimestamp: event.timestamp,
      actionEventId: event.id,
    })
    if (alt) hits.push(alt)

    const del = findDelegatedPolicyCircumvention({
      memory: this.memory,
      sessionId: event.session.id,
      agentId,
      parentOf: (id) => this.parentOf(id),
      action,
      actionTimestamp: event.timestamp,
      actionEventId: event.id,
    })
    if (del) hits.push(del)
    return hits
  }

  private privilegeHits(event: HarnessEvent): DetectionHit[] {
    const childId = event.agent?.id
    const parentId = event.agent?.parent_agent_id ?? undefined
    if (!childId || !parentId) return []

    if (event.capability?.available) {
      this.snapshotObserved.add(childId)
      this.snapshotByAgent.set(childId, [...event.capability.available].sort())
    }

    if (!this.snapshotObserved.has(parentId) || !this.snapshotObserved.has(childId)) {
      return []
    }

    const hit = findDelegationPrivilegeExpansion({
      parentAgentId: parentId,
      childAgentId: childId,
      parentAvailable: this.snapshotByAgent.get(parentId) ?? [],
      childAvailable: this.snapshotByAgent.get(childId) ?? [],
      sessionId: event.session.id,
      spawnEventId: event.id,
      timestamp: event.timestamp,
    })
    return hit ? [hit] : []
  }

  private toDetection(hit: DetectionHit, trigger: HarnessEvent): HarnessEvent | undefined {
    const key = `${hit.kind}|${hit.evidence.blocked_event_id}|${hit.evidence.action_event_id}`
    if (this.raised.has(key)) return undefined
    this.raised.add(key)
    return buildDetectionEvent(hit, trigger)
  }
}
