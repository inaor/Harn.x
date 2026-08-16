import type { FlightRecorder } from '../core/recorder.js'

export function renderReplay(recorder: FlightRecorder, sessionId: string): string {
  const session = recorder.getSession(sessionId)
  if (!session) return `Session not found: ${sessionId}`

  const lines: string[] = []
  lines.push(`SESSION: ${sessionId}`)
  lines.push('')
  lines.push('Objective:')
  lines.push(session.objective?.description ?? '(unknown)')
  lines.push('')

  const agent = session.events.find(e => e.event_type === 'agent.started')
  lines.push('Agent:')
  lines.push(agent?.agent?.id ?? '(unknown)')
  lines.push('')
  lines.push('────────────────────────────────────')
  lines.push('')

  for (const e of session.events) {
    lines.push(e.timestamp)
    lines.push(label(e.event_type))
    lines.push('')

    if (e.context) {
      lines.push(`source:`)
      lines.push(`${e.context.source ?? e.context.source_type}`)
      lines.push('')
      lines.push(`trust:`)
      lines.push(e.context.trust.toUpperCase())
      if (e.context.excerpt) {
        lines.push('')
        lines.push(`excerpt:`)
        lines.push(e.context.excerpt)
      }
      lines.push('')
      lines.push('        ↓')
      lines.push('')
    }

    if (e.tool?.name && (e.event_type === 'tool.requested' || e.event_type === 'shell.command_requested' || e.event_type === 'mcp.tool_requested')) {
      lines.push(`tool:`)
      lines.push(e.tool.name)
      if (e.action?.target && e.action.target !== e.tool.name) {
        lines.push('')
        lines.push(`target:`)
        lines.push(String(e.action.target))
      }
      const cmd = e.action?.arguments && typeof e.action.arguments === 'object'
        ? (e.action.arguments as any).command
        : undefined
      if (cmd) {
        lines.push('')
        lines.push(`command:`)
        lines.push(String(cmd))
      }
      lines.push('')
      lines.push('        ↓')
      lines.push('')
    }

    if (e.event_type === 'policy.decision') {
      lines.push('HarnessSec Policy')
      lines.push('')
      lines.push(`rule:`)
      lines.push(e.policy?.rule ?? '-')
      lines.push('')
      lines.push(`decision:`)
      lines.push((e.policy?.decision ?? 'allow').toUpperCase())
      if (e.policy?.reason) {
        lines.push('')
        lines.push(`reason:`)
        lines.push(e.policy.reason)
      }
      lines.push('')
      lines.push('        ↓')
      lines.push('')
    }

    if (e.event_type === 'tool.denied') {
      lines.push('BLOCKED BEFORE EXECUTION')
      lines.push('')
      lines.push('        ↓')
      lines.push('')
    }

    if (e.event_type === 'policy.aftermath') {
      lines.push('Agent reaction after block')
      lines.push('')
      lines.push(`selected alternate tool:`)
      lines.push(e.tool?.name ?? '-')
      lines.push('')
      lines.push('HarnessSec: possible policy bypass behavior (recorded)')
      lines.push('')
      lines.push('        ↓')
      lines.push('')
    }

    if (e.event_type === 'behavior.detection' && e.detection) {
      lines.push('BEHAVIORAL DETECTION')
      lines.push('')
      lines.push(`kind:`)
      lines.push(e.detection.kind)
      lines.push('')
      lines.push(`severity:`)
      lines.push(e.detection.severity.toUpperCase())
      lines.push('')
      lines.push(`title:`)
      lines.push(e.detection.title)
      lines.push('')
      lines.push('        ↓')
      lines.push('')
    }
  }

  lines.push('Session status:')
  lines.push(session.ended_at ? 'ENDED' : 'ACTIVE')
  lines.push('')
  lines.push('Agent lineage:')
  lines.push(recorder.lineage.tree(sessionId))
  lines.push('')
  if (agent?.agent?.id) {
    lines.push('Capabilities:')
    lines.push(recorder.capabilities.render(sessionId, agent.agent.id))
  }

  return lines.join('\n')
}

function label(t: string): string {
  switch (t) {
    case 'context.introduced': return 'Context introduced'
    case 'objective.captured': return 'Objective captured'
    case 'tool.requested': return 'Tool request'
    case 'shell.command_requested': return 'Shell command requested'
    case 'mcp.tool_requested': return 'MCP tool requested'
    case 'policy.decision': return 'Policy decision'
    case 'tool.denied': return 'Tool denied'
    case 'tool.completed': return 'Tool completed'
    case 'policy.aftermath': return 'Post-block behavior'
    case 'behavior.detection': return 'Behavioral detection'
    case 'agent.started': return 'Agent started'
    case 'session.started': return 'Session started'
    case 'subagent.spawned': return 'Sub-agent spawned'
    default: return t
  }
}
