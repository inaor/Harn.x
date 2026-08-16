import { normalizeAction } from './normalize.js'

export interface IncidentSessionView {
  getSession(sessionId: string): {
    session_id: string
    events: Array<{
      timestamp: string
      event_type: string
      agent?: { id?: string; parent_agent_id?: string | null }
      context?: { trust?: string }
      tool?: { name?: string }
      action?: { arguments?: Record<string, unknown>; target?: string }
      policy?: { decision?: string; rule?: string }
      detection?: { kind?: string; title?: string }
      links?: { attempted_after?: string; correlated_with?: string }
    }>
  } | undefined
}

function clock(iso: string): string {
  try {
    return new Date(iso).toISOString().slice(11, 19)
  } catch {
    return iso
  }
}

/** Render HARN.X INCIDENT timeline for a session. */
export function renderIncident(store: IncidentSessionView, sessionId: string): string {
  const session = store.getSession(sessionId)
  if (!session) return `Session not found: ${sessionId}`

  const detections = session.events.filter(e => e.event_type === 'behavior.detection')
  const lines: string[] = []
  lines.push('HARN.X INCIDENT')
  lines.push('')
  if (detections.length) {
    const primary = detections.find(d => d.detection?.kind === 'agent.delegated_policy_circumvention')
      ?? detections.find(d => d.detection?.kind === 'agent.policy_circumvention')
      ?? detections[0]
    lines.push('Detection:')
    lines.push(primary.detection?.kind === 'agent.delegated_policy_circumvention'
      ? 'Autonomous Policy Circumvention (delegated)'
      : primary.detection?.kind === 'agent.policy_circumvention'
        ? 'Autonomous Policy Circumvention'
        : (primary.detection?.title ?? 'Behavioral detection'))
    lines.push('')
  } else {
    lines.push('Detection:')
    lines.push('(none)')
    lines.push('')
  }

  lines.push('Session:')
  lines.push(sessionId)
  lines.push('')

  const rootAgent = session.events.find(e => e.event_type === 'agent.started')?.agent?.id
    ?? session.events.find(e => e.agent?.id && !e.agent.parent_agent_id)?.agent?.id
  lines.push('Agent:')
  lines.push(rootAgent ?? '(unknown)')
  lines.push('')
  lines.push('Timeline:')
  lines.push('')

  for (const e of session.events) {
    const t = clock(e.timestamp)

    if (e.event_type === 'context.introduced' && e.context?.trust === 'untrusted') {
      lines.push(t)
      lines.push('[OBSERVED] Untrusted context introduced')
      lines.push('')
      continue
    }

    if (e.event_type === 'tool.requested' && e.tool?.name) {
      const norm = normalizeAction(e as Parameters<typeof normalizeAction>[0])
      lines.push(t)
      lines.push('[OBSERVED] Agent requested tool:')
      lines.push(e.tool.name)
      lines.push(`[DERIVED] ${norm.category}${norm.target ? ` ${norm.target}` : ''} via ${norm.capability} (${norm.level})`)
      if (e.links?.attempted_after || e.links?.correlated_with) {
        lines.push('[CORRELATED] post-block / weak association link present')
      }
      lines.push('')
      continue
    }

    if (e.event_type === 'policy.decision' && e.policy?.decision === 'block') {
      lines.push(t)
      lines.push('[OBSERVED] BLOCKED')
      if (e.policy.rule) lines.push(`rule: ${e.policy.rule}`)
      lines.push('')
      continue
    }

    if (e.event_type === 'subagent.spawned') {
      lines.push(t)
      lines.push('[OBSERVED] Agent delegated to:')
      lines.push(e.agent?.id ?? '(child)')
      lines.push('')
      continue
    }

    if (e.event_type === 'behavior.detection' && e.detection) {
      lines.push(t)
      lines.push('[DERIVED] behavioral detection')
      if (e.detection.kind === 'agent.policy_circumvention') {
        lines.push('DETECTION:')
        lines.push('Alternate capability circumvention')
      } else if (e.detection.kind === 'agent.delegated_policy_circumvention') {
        lines.push('CRITICAL:')
        lines.push('Delegated policy circumvention')
      } else {
        lines.push('DETECTION:')
        lines.push(e.detection.title ?? e.detection.kind ?? 'detection')
      }
      lines.push('')
    }
  }

  return lines.join('\n')
}
