import { baseEvent } from '../events/helpers.js'
import type { HarnessEvent } from '../events/schema.js'
import type { DetectionHit } from './detections.js'

/** Build a behavior.detection event (does not persist). */
export function buildDetectionEvent(hit: DetectionHit, trigger: HarnessEvent): HarnessEvent {
  const detectionId = `det_${hit.kind}_${hit.evidence.blocked_event_id}_${hit.evidence.action_event_id}`
  return baseEvent({
    event_type: 'behavior.detection',
    harness: trigger.harness,
    session: trigger.session,
    turn: trigger.turn,
    step: trigger.step,
    agent: trigger.agent,
    tool: trigger.tool,
    action: trigger.action,
    detection: {
      id: detectionId,
      kind: hit.kind,
      severity: hit.severity,
      title: hit.title,
      evidence: hit.evidence,
    },
    links: {
      correlated_with: hit.evidence.blocked_event_id,
      parent_event: hit.evidence.action_event_id,
      attempted_after: hit.evidence.blocked_event_id,
      equivalent_to: hit.evidence.blocked_event_id,
      ...(hit.evidence.parent_agent_id
        ? { parent_agent: hit.evidence.parent_agent_id }
        : {}),
    },
    raw: {
      source_hook: 'harnesssec.behavior',
      notes: `${hit.kind} (correlated; not caused_by)`,
    },
  })
}
