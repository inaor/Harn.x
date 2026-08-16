import type { HarnessEvent, PolicyDecisionKind } from '../events/schema.js'
import { baseEvent } from '../events/helpers.js'
import type { FlightRecorder } from '../core/recorder.js'

export interface PolicyRule {
  id: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  action: Exclude<PolicyDecisionKind, 'allow'>
  match: (event: HarnessEvent, ctx: PolicyContext) => boolean
  reason: (event: HarnessEvent, ctx: PolicyContext) => string
}

export interface PolicyContext {
  hasUntrustedContext: boolean
  untrustedContextEventId?: string
  recentToolNames: string[]
  availableTools: string[]
  priorBlockEventId?: string
}

export interface PolicyVerdict {
  decision: PolicyDecisionKind
  rule?: PolicyRule
  reason?: string
  event: HarnessEvent
}

export class PolicyEngine {
  constructor(
    private readonly recorder: FlightRecorder,
    private readonly rules: PolicyRule[],
  ) {}

  evaluateToolRequest(event: HarnessEvent): PolicyVerdict {
    const ctx = this.buildContext(event)

    if (ctx.priorBlockEventId) {
      this.recordAftermath(ctx.priorBlockEventId, event)
    }

    for (const rule of this.rules) {
      if (!rule.match(event, ctx)) continue
      const reason = rule.reason(event, ctx)
      const decisionEvent = baseEvent({
        event_type: 'policy.decision',
        session: event.session,
        agent: event.agent,
        tool: event.tool,
        action: event.action,
        policy: {
          decision: rule.action,
          rule: rule.id,
          severity: rule.severity,
          reason,
        },
        links: {
          policy_decision_for: event.id,
          ...ctx.untrustedContextEventId ? { context_source: ctx.untrustedContextEventId } : {},
        },
        raw: { source_hook: 'harnesssec.policy' },
      })
      this.recorder.record(decisionEvent)
      return { decision: rule.action, rule, reason, event: decisionEvent }
    }

    const allowEvent = baseEvent({
      event_type: 'policy.decision',
      session: event.session,
      agent: event.agent,
      tool: event.tool,
      policy: { decision: 'allow', reason: 'no matching rule' },
      links: { policy_decision_for: event.id },
      raw: { source_hook: 'harnesssec.policy' },
    })
    this.recorder.record(allowEvent)
    return { decision: 'allow', reason: 'no matching rule', event: allowEvent }
  }

  private recordAftermath(blockedPolicyEventId: string, nextToolEvent: HarnessEvent): void {
    const session = this.recorder.getSession(nextToolEvent.session.id)
    const already = session?.events.some(
      e => e.event_type === 'policy.aftermath' && e.links?.caused_by === blockedPolicyEventId,
    )
    if (already) return

    this.recorder.record(baseEvent({
      event_type: 'policy.aftermath',
      session: nextToolEvent.session,
      agent: nextToolEvent.agent,
      tool: nextToolEvent.tool,
      action: nextToolEvent.action,
      links: {
        caused_by: blockedPolicyEventId,
        parent_event: nextToolEvent.id,
      },
      raw: {
        source_hook: 'harnesssec.policy.aftermath',
        notes: 'Agent requested another tool after a prior BLOCK',
      },
    }))
  }

  private buildContext(event: HarnessEvent): PolicyContext {
    const session = this.recorder.getSession(event.session.id)
    const events = session?.events ?? []
    const agentId = event.agent?.id
    const agentEvents = events.filter(e => !agentId || e.agent?.id === agentId)

    const untrusted = [...agentEvents].reverse().find(
      e => e.event_type === 'context.introduced' && e.context?.trust === 'untrusted',
    )

    const priorBlock = [...agentEvents].reverse().find(
      e => e.event_type === 'policy.decision' && e.policy?.decision === 'block',
    )

    const recentToolNames = agentEvents
      .filter(e => e.event_type === 'tool.requested' || e.event_type === 'tool.denied')
      .slice(-8)
      .map(e => e.tool?.name)
      .filter((n): n is string => !!n)

    const availableTools = agentId
      ? this.recorder.capabilities.availableFor(agentId)
      : []

    return {
      hasUntrustedContext: !!untrusted,
      untrustedContextEventId: untrusted?.id,
      recentToolNames,
      availableTools,
      priorBlockEventId: priorBlock?.id,
    }
  }
}
