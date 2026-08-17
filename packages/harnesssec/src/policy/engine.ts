import type { HarnessEvent, PolicyDecisionKind } from '../events/schema.js'
import { baseEvent } from '../events/helpers.js'
import type { FlightRecorder } from '../core/recorder.js'
import { normalizeAction, type NormalizedAction } from '../behavior/normalize.js'

export interface PolicyRule {
  id: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  action: Exclude<PolicyDecisionKind, 'allow'>
  match: (event: HarnessEvent, ctx: PolicyContext) => boolean
  reason: (event: HarnessEvent, ctx: PolicyContext) => string
}

export interface PolicyContext {
  /** Same-turn untrusted context only. */
  hasUntrustedContext: boolean
  untrustedContextEventId?: string
  turn?: number
  recentToolNames: string[]
  availableTools: string[]
  priorBlockEventId?: string
  mcpTrust?: 'trusted' | 'untrusted' | 'unknown'
  /** Deterministic normalized action for resource-centric rules (vendor-neutral). */
  normalized: NormalizedAction
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
        harness: event.harness,
        session: event.session,
        turn: event.turn,
        step: event.step,
        agent: event.agent,
        tool: event.tool,
        action: event.action,
        mcp: event.mcp,
        policy: {
          decision: rule.action,
          rule: rule.id,
          severity: rule.severity,
          reason,
        },
        links: {
          policy_decision_for: event.id,
          ...ctx.untrustedContextEventId
            ? {
              candidate_context_source: ctx.untrustedContextEventId,
              correlated_with: ctx.untrustedContextEventId,
            }
            : {},
        },
        raw: {
          source_hook: 'harnesssec.policy',
          notes: `normalized=${ctx.normalized.category}:${ctx.normalized.target || '(empty)'};level=${ctx.normalized.level}`,
          normalized: {
            category: ctx.normalized.category,
            target: ctx.normalized.target,
            level: ctx.normalized.level,
            capability: ctx.normalized.capability,
            tool_name: ctx.normalized.tool_name,
          },
        },
      })
      this.recorder.record(decisionEvent)
      return { decision: rule.action, rule, reason, event: decisionEvent }
    }

    const allowEvent = baseEvent({
      event_type: 'policy.decision',
      harness: event.harness,
      session: event.session,
      turn: event.turn,
      step: event.step,
      agent: event.agent,
      tool: event.tool,
      policy: { decision: 'allow', reason: 'no matching rule' },
      links: { policy_decision_for: event.id },
      raw: {
        source_hook: 'harnesssec.policy',
        notes: `normalized=${ctx.normalized.category}:${ctx.normalized.target || '(empty)'};level=${ctx.normalized.level}`,
        normalized: {
          category: ctx.normalized.category,
          target: ctx.normalized.target,
          level: ctx.normalized.level,
          capability: ctx.normalized.capability,
          tool_name: ctx.normalized.tool_name,
        },
      },
    })
    this.recorder.record(allowEvent)
    return { decision: 'allow', reason: 'no matching rule', event: allowEvent }
  }

  private recordAftermath(blockedPolicyEventId: string, nextToolEvent: HarnessEvent): void {
    const session = this.recorder.getSession(nextToolEvent.session.id)
    const already = session?.events.some(
      e => e.event_type === 'policy.aftermath'
        && (e.links?.correlated_with === blockedPolicyEventId || e.links?.caused_by === blockedPolicyEventId),
    )
    if (already) return

    this.recorder.record(baseEvent({
      event_type: 'policy.aftermath',
      harness: nextToolEvent.harness,
      session: nextToolEvent.session,
      turn: nextToolEvent.turn,
      step: nextToolEvent.step,
      agent: nextToolEvent.agent,
      tool: nextToolEvent.tool,
      action: nextToolEvent.action,
      links: {
        // Temporal sequence after a block — correlation, not proven causal intent.
        correlated_with: blockedPolicyEventId,
        parent_event: nextToolEvent.id,
      },
      raw: {
        source_hook: 'harnesssec.policy.aftermath',
        notes: 'Agent requested another tool after a prior BLOCK (correlated, not caused_by)',
      },
    }))
  }

  private buildContext(event: HarnessEvent): PolicyContext {
    const session = this.recorder.getSession(event.session.id)
    const events = session?.events ?? []
    const agentId = event.agent?.id
    const agentEvents = events.filter(e => !agentId || e.agent?.id === agentId)

    const turn = event.turn
      ?? (typeof (event.action?.arguments as any)?.turn === 'number'
        ? (event.action!.arguments as any).turn as number
        : event.context?.turn)

    let untrustedId: string | undefined
    if (agentId && turn !== undefined) {
      untrustedId = this.recorder.provenance.candidateUntrustedForStep(event.session.id, agentId, turn)
    }

    // Same-turn context.introduced events that haven't been indexed yet in provenance
    // (e.g. recorded in same tick before observe) — fall back to scanning this turn's events.
    if (!untrustedId && turn !== undefined) {
      const sameTurn = [...agentEvents].reverse().find(e =>
        e.event_type === 'context.introduced'
        && e.context?.trust === 'untrusted'
        && e.context.turn === turn,
      )
      untrustedId = sameTurn?.id
    }

    const priorBlock = [...agentEvents].reverse().find(
      e => e.event_type === 'policy.decision' && e.policy?.decision === 'block',
    )

    const recentToolNames = agentEvents
      .filter(e => e.event_type === 'tool.requested' || e.event_type === 'tool.denied')
      .slice(-8)
      .map(e => e.tool?.name)
      .filter((n): n is string => !!n)

    const availableTools = agentId
      ? this.recorder.capabilities.availableFor(event.session.id, agentId)
      : []

    return {
      hasUntrustedContext: !!untrustedId,
      untrustedContextEventId: untrustedId,
      turn,
      recentToolNames,
      availableTools,
      priorBlockEventId: priorBlock?.id,
      mcpTrust: event.mcp?.trust,
      normalized: normalizeAction(event),
    }
  }
}
