/** Phase 4B — `harnesssec why` rendering (no LLM). */

import type { FlightRecorder } from '../core/recorder.js'
import type { HarnessEvent } from '../events/schema.js'
import { normalizeAction } from '../behavior/normalize.js'
import { correlateAgentReaction } from '../behavior/reaction.js'

function resolveBlock(sessionEvents: HarnessEvent[], id: string): HarnessEvent | undefined {
  const direct = sessionEvents.find(e => e.id === id)
  if (direct?.event_type === 'policy.decision' && direct.policy?.decision === 'block') {
    return direct
  }
  if (direct?.links?.policy_decision_for) {
    const linked = sessionEvents.find(e => e.id === direct.links!.policy_decision_for)
    if (linked?.event_type === 'policy.decision' && linked.policy?.decision === 'block') {
      return linked
    }
  }
  if (direct?.links?.blocked_by) {
    const linked = sessionEvents.find(e => e.id === direct.links!.blocked_by)
    if (linked?.event_type === 'policy.decision' && linked.policy?.decision === 'block') {
      return linked
    }
  }
  // tool.denied → preceding block for same agent
  if (direct?.event_type === 'tool.denied') {
    const blocks = sessionEvents.filter(
      e => e.event_type === 'policy.decision' && e.policy?.decision === 'block',
    )
    return blocks[blocks.length - 1]
  }
  const blocks = sessionEvents.filter(
    e => e.event_type === 'policy.decision' && e.policy?.decision === 'block',
  )
  return blocks[blocks.length - 1]
}

function findBlockedTool(events: HarnessEvent[], block: HarnessEvent): HarnessEvent | undefined {
  const forId = block.links?.policy_decision_for
  if (forId) {
    const hit = events.find(e => e.id === forId)
    if (hit) return hit
  }
  const idx = events.findIndex(e => e.id === block.id)
  for (let i = idx - 1; i >= 0; i--) {
    const e = events[i]
    if (
      e.event_type === 'tool.requested'
      || e.event_type === 'shell.command_requested'
      || e.event_type === 'mcp.tool_requested'
    ) {
      return e
    }
  }
  return undefined
}

/** Render Phase 4B five-question WHY output. */
export function renderWhy(recorder: FlightRecorder, id: string): string {
  const sessions = recorder.listSessions()
  const session = recorder.getSession(id)
    ?? sessions.find(s => s.events.some(e => e.id === id))
  if (!session) {
    return `session/event not found: ${id}`
  }

  // Idempotent backfill so old stores get agent.reaction without mutating detection bars.
  recorder.backfillReactions(session.session_id)
  const fresh = recorder.getSession(session.session_id) ?? session
  const events = fresh.events

  const block = resolveBlock(events, id)
  if (!block) {
    return [
      'HARN.X WHY',
      '',
      `Session: ${fresh.session_id}`,
      '',
      'No policy BLOCK found to explain.',
      'No LLM inference was used.',
    ].join('\n')
  }

  const blockedTool = findBlockedTool(events, block)
  const norm = blockedTool ? normalizeAction(blockedTool) : undefined
  const reactionEvent = events.find(
    e => e.event_type === 'agent.reaction'
      && e.reaction?.for_policy_decision_id === block.id,
  )
  const reaction = reactionEvent?.reaction
    ?? correlateAgentReaction(events, block.id)

  const detections = events.filter(
    e => e.event_type === 'behavior.detection'
      && (
        e.detection?.evidence?.blocked_event_id === block.id
        || e.links?.correlated_with === block.id
        || e.links?.attempted_after === block.id
      ),
  )

  const supportIds = reaction.supporting_event_ids ?? []
  const nextLines = supportIds.length
    ? supportIds.map((sid) => {
      const ev = events.find(e => e.id === sid)
      if (!ev) return `- ${sid}`
      return `- ${ev.event_type} ${ev.tool?.name ?? ''} ${ev.id}`.trim()
    })
    : ['(none observed)']

  const lines: string[] = []
  lines.push('HARN.X WHY')
  lines.push('')
  lines.push(`Session: ${fresh.session_id}`)
  lines.push(`Harness: ${block.harness?.name ?? '-'}`)
  lines.push(`Block event: ${block.id}`)
  lines.push('')
  lines.push('What was blocked?')
  lines.push(`  tool:     ${blockedTool?.tool?.name ?? norm?.tool_name ?? '-'}`)
  lines.push(`  target:   ${norm?.target || blockedTool?.action?.target || '-'}`)
  lines.push(
    `  category: ${norm ? `${norm.category} (${norm.level})` : '-'}`,
  )
  lines.push('')
  lines.push('Why?')
  lines.push(`  rule:     ${block.policy?.rule ?? '-'}`)
  lines.push(`  decision: ${(block.policy?.decision ?? 'block').toUpperCase()}`)
  lines.push(`  reason:   ${block.policy?.reason ?? '-'}`)
  lines.push('')
  lines.push('What did the agent do next?')
  lines.push(`  reaction: ${reaction.type}`)
  lines.push(`  evidence: ${reaction.evidence}`)
  lines.push(`  window:   ${reaction.window_ms}ms`)
  lines.push(`  summary:  ${reaction.summary}`)
  lines.push('  next:')
  for (const n of nextLines) lines.push(`    ${n}`)
  lines.push('')
  lines.push('Did Harn.x classify that reaction as security-relevant?')
  if (!detections.length) {
    lines.push('  no')
    lines.push('  (agent.reaction is factual only; no linked behavior.detection)')
  } else {
    lines.push('  yes — separate behavior.detection evidence:')
    for (const d of detections) {
      lines.push(`  - ${d.detection?.kind} (${d.detection?.severity}) ${d.detection?.title ?? ''}`)
    }
  }
  lines.push('')
  lines.push('What evidence supports the conclusion?')
  lines.push(`  - policy.decision ${block.id} @ ${block.timestamp}`)
  if (reactionEvent) {
    lines.push(
      `  - agent.reaction ${reactionEvent.id} @ ${reactionEvent.timestamp} type=${reaction.type}`,
    )
  } else {
    lines.push(`  - agent.reaction (derived) type=${reaction.type}`)
  }
  for (const sid of supportIds) {
    const ev = events.find(e => e.id === sid)
    lines.push(`  - supporting ${ev?.event_type ?? 'event'} ${sid}`)
  }
  for (const d of detections) {
    lines.push(`  - behavior.detection ${d.id} kind=${d.detection?.kind}`)
  }
  lines.push('')
  lines.push('No LLM inference was used.')
  lines.push('No caused_by claim for agent reaction.')
  return lines.join('\n')
}
