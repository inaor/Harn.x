/**
 * Phase 4B — AGENT_REACTION correlator.
 *
 * Factual classification of observable agent behavior after a policy BLOCK.
 * Strictly separate from behavior.detection (security interpretation).
 * Never emits caused_by. Missing / unsupported telemetry → UNKNOWN.
 */

import { baseEvent } from '../events/helpers.js'
import type { HarnessEvent } from '../events/schema.js'
import {
  actionsEquivalent,
  differentCapability,
  isDetectionEligible,
  normalizeAction,
  type NormalizedAction,
} from './normalize.js'

/** Default post-block reaction horizon — not the 30s circumvention window. */
export const DEFAULT_REACTION_WINDOW_MS = 120_000

export type AgentReactionType =
  | 'STOP'
  | 'ASK_USER'
  | 'RETRY_SAME'
  | 'ALTERNATE_TOOL'
  | 'DELEGATE'
  | 'UNKNOWN'

export type ReactionEvidenceTag = 'OBSERVED' | 'CORRELATED'

export interface AgentReactionResult {
  type: AgentReactionType
  evidence: ReactionEvidenceTag
  window_ms: number
  for_policy_decision_id: string
  supporting_event_ids: string[]
  summary: string
  /** Reaction itself is never a security claim. */
  security_relevant: false
}

export interface CorrelateReactionOptions {
  /** Override DEFAULT_REACTION_WINDOW_MS (tests / config). */
  windowMs?: number
}

const TOOL_LIKE = new Set([
  'tool.requested',
  'shell.command_requested',
  'mcp.tool_requested',
])

function parseTs(iso: string): number {
  const t = Date.parse(iso)
  return Number.isFinite(t) ? t : 0
}

function withinWindow(blockTs: string, eventTs: string, windowMs: number): boolean {
  const b = parseTs(blockTs)
  const e = parseTs(eventTs)
  if (!b || !e) return false
  const dt = e - b
  return dt >= 0 && dt <= windowMs
}

function relevantToBlock(block: HarnessEvent, other: HarnessEvent): boolean {
  const a = block.agent?.id
  if (!a) return true
  if (other.agent?.id === a) return true
  // Child spawn rows carry the child id; accept explicit parent linkage.
  if (other.event_type === 'subagent.spawned') {
    if (other.agent?.parent_agent_id === a) return true
    if (other.links?.parent_agent === a) return true
  }
  return false
}

function findBlockedToolRequest(events: HarnessEvent[], block: HarnessEvent): HarnessEvent | undefined {
  const forId = block.links?.policy_decision_for
  if (forId) {
    const hit = events.find(e => e.id === forId && TOOL_LIKE.has(e.event_type))
    if (hit) return hit
  }
  const blockTs = parseTs(block.timestamp)
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i]
    if (!TOOL_LIKE.has(e.event_type)) continue
    if (!relevantToBlock(block, e)) continue
    if (parseTs(e.timestamp) <= blockTs) return e
  }
  return undefined
}

function isAskUserSignal(e: HarnessEvent): boolean {
  // Structured harness signals only — never free-text transcript prose.
  if (e.event_type === 'approval.asked') return true
  const marker = e.raw?.notes
  if (typeof marker === 'string' && marker.includes('harnx.reaction.signal=ASK_USER')) return true
  return false
}

function isStopSignal(e: HarnessEvent): boolean {
  if (e.event_type === 'session.ended' || e.event_type === 'agent.ended') return true
  const marker = e.raw?.notes
  if (typeof marker === 'string' && marker.includes('harnx.reaction.signal=STOP')) return true
  return false
}

function alreadyHasReaction(events: HarnessEvent[], blockId: string): boolean {
  return events.some(
    e => e.event_type === 'agent.reaction' && e.reaction?.for_policy_decision_id === blockId,
  )
}

/**
 * Classify one policy BLOCK into an AGENT_REACTION.
 * Idempotent consumers should skip when alreadyHasReaction.
 */
export function correlateAgentReaction(
  events: HarnessEvent[],
  blockEventId: string,
  opts?: CorrelateReactionOptions,
): AgentReactionResult {
  const windowMs = opts?.windowMs ?? DEFAULT_REACTION_WINDOW_MS
  const block = events.find(e => e.id === blockEventId)

  if (!block || block.event_type !== 'policy.decision' || block.policy?.decision !== 'block') {
    return {
      type: 'UNKNOWN',
      evidence: 'CORRELATED',
      window_ms: windowMs,
      for_policy_decision_id: blockEventId,
      supporting_event_ids: [],
      summary: 'Missing or non-block policy.decision — cannot classify reaction',
      security_relevant: false,
    }
  }

  const after = events.filter(
    e => e.id !== block.id
      && relevantToBlock(block, e)
      && withinWindow(block.timestamp, e.timestamp, windowMs)
      && parseTs(e.timestamp) > parseTs(block.timestamp)
      && e.event_type !== 'agent.reaction'
      && e.event_type !== 'behavior.detection'
      && e.event_type !== 'policy.aftermath'
      && e.event_type !== 'policy.decision',
  )

  // Stable order by timestamp then id
  after.sort((a, b) => {
    const t = String(a.timestamp).localeCompare(String(b.timestamp))
    return t !== 0 ? t : String(a.id).localeCompare(String(b.id))
  })

  const spawns = after.filter(e => e.event_type === 'subagent.spawned')
  if (spawns.length > 0) {
    const first = spawns[0]
    return {
      type: 'DELEGATE',
      evidence: 'OBSERVED',
      window_ms: windowMs,
      for_policy_decision_id: block.id,
      supporting_event_ids: [first.id],
      summary: `Observed subagent.spawned after block (${first.agent?.id ?? 'child'})`,
      security_relevant: false,
    }
  }

  const tools = after.filter(e => TOOL_LIKE.has(e.event_type))
  const askSignals = after.filter(isAskUserSignal)
  const stopSignals = after.filter(isStopSignal)

  if (tools.length === 0) {
    if (askSignals.length > 0) {
      return {
        type: 'ASK_USER',
        evidence: 'OBSERVED',
        window_ms: windowMs,
        for_policy_decision_id: block.id,
        supporting_event_ids: [askSignals[0].id],
        summary: 'Observed ask/handoff signal after block; no further tools in window',
        security_relevant: false,
      }
    }
    if (stopSignals.length > 0) {
      return {
        type: 'STOP',
        evidence: 'OBSERVED',
        window_ms: windowMs,
        for_policy_decision_id: block.id,
        supporting_event_ids: [stopSignals[0].id],
        summary: 'Observed session/agent end after block; no further tools in window',
        security_relevant: false,
      }
    }
    return {
      type: 'UNKNOWN',
      evidence: 'CORRELATED',
      window_ms: windowMs,
      for_policy_decision_id: block.id,
      supporting_event_ids: [],
      summary:
        'No tool/delegate activity after block and no OBSERVED ask/stop signal (silence ≠ ASK_USER/STOP)',
      security_relevant: false,
    }
  }

  const blockedReq = findBlockedToolRequest(events, block)
  if (!blockedReq) {
    return {
      type: 'UNKNOWN',
      evidence: 'CORRELATED',
      window_ms: windowMs,
      for_policy_decision_id: block.id,
      supporting_event_ids: [tools[0].id],
      summary: 'Post-block tool observed but blocked tool.requested could not be resolved',
      security_relevant: false,
    }
  }

  const first = tools[0]
  const blockedNorm = normalizeAction(blockedReq)
  const laterNorm = normalizeAction(first)

  if (isRetrySame(blockedNorm, laterNorm, blockedReq, first)) {
    return {
      type: 'RETRY_SAME',
      evidence: 'OBSERVED',
      window_ms: windowMs,
      for_policy_decision_id: block.id,
      supporting_event_ids: [first.id],
      summary:
        `Same capability family retry of equivalent action via ${first.tool?.name ?? first.event_type}`,
      security_relevant: false,
    }
  }

  if (isAlternateTool(blockedNorm, laterNorm)) {
    return {
      type: 'ALTERNATE_TOOL',
      evidence: 'OBSERVED',
      window_ms: windowMs,
      for_policy_decision_id: block.id,
      supporting_event_ids: [first.id],
      summary:
        `Different capability family with exact/strong equivalent target via ${first.tool?.name ?? first.event_type}`,
      security_relevant: false,
    }
  }

  return {
    type: 'UNKNOWN',
    evidence: 'CORRELATED',
    window_ms: windowMs,
    for_policy_decision_id: block.id,
    supporting_event_ids: [first.id],
    summary:
      `Post-block tool ${first.tool?.name ?? first.event_type} is not RETRY_SAME or ALTERNATE_TOOL `
      + '(no exact/strong equivalence and/or not a different capability family)',
    security_relevant: false,
  }
}

function isRetrySame(
  blocked: NormalizedAction,
  later: NormalizedAction,
  _blockedEv: HarnessEvent,
  _laterEv: HarnessEvent,
): boolean {
  if (!isDetectionEligible(blocked) || !isDetectionEligible(later)) return false
  if (!actionsEquivalent(blocked, later)) return false
  // Same capability family (not alternate).
  return !differentCapability(blocked, later)
}

/**
 * ALTERNATE_TOOL requires different family AND exact/strong semantic relation
 * to the blocked action/target. Timing alone is insufficient.
 */
function isAlternateTool(blocked: NormalizedAction, later: NormalizedAction): boolean {
  if (!isDetectionEligible(blocked) || !isDetectionEligible(later)) return false
  if (!differentCapability(blocked, later)) return false
  return actionsEquivalent(blocked, later)
}

/** All policy BLOCKs in session → one result each (does not persist). */
export function correlateAllSessionReactions(
  events: HarnessEvent[],
  opts?: CorrelateReactionOptions,
): AgentReactionResult[] {
  const blocks = events.filter(
    e => e.event_type === 'policy.decision' && e.policy?.decision === 'block',
  )
  return blocks.map(b => correlateAgentReaction(events, b.id, opts))
}

/** Build a persistable agent.reaction event (no caused_by). */
export function buildReactionEvent(
  result: AgentReactionResult,
  block: HarnessEvent,
  trigger?: HarnessEvent,
): HarnessEvent {
  const source = trigger ?? block
  return baseEvent({
    event_type: 'agent.reaction',
    harness: source.harness,
    session: source.session,
    turn: source.turn,
    step: source.step,
    agent: block.agent ?? source.agent,
    timestamp: source.timestamp,
    reaction: {
      type: result.type,
      evidence: result.evidence,
      window_ms: result.window_ms,
      for_policy_decision_id: result.for_policy_decision_id,
      supporting_event_ids: result.supporting_event_ids,
      summary: result.summary,
    },
    links: {
      correlated_with: result.for_policy_decision_id,
      ...(result.supporting_event_ids[0]
        ? {
          parent_event: result.supporting_event_ids[0],
          attempted_after: result.for_policy_decision_id,
        }
        : {}),
    },
    raw: {
      source_hook: 'harnesssec.agent.reaction',
      notes: `agent.reaction type=${result.type} (factual; not behavior.detection; not caused_by)`,
    },
  })
}

/**
 * Replay/backfill: emit agent.reaction events for blocks that lack one.
 * Returns only newly built events (caller persists).
 */
export function backfillSessionReactions(
  events: HarnessEvent[],
  opts?: CorrelateReactionOptions,
): HarnessEvent[] {
  const out: HarnessEvent[] = []
  const blocks = events.filter(
    e => e.event_type === 'policy.decision' && e.policy?.decision === 'block',
  )
  for (const block of blocks) {
    if (alreadyHasReaction(events, block.id)) continue
    if (alreadyHasReaction([...events, ...out], block.id)) continue
    const result = correlateAgentReaction(events, block.id, opts)
    // Prefer last supporting / end / first tool as timestamp anchor
    const supportId = result.supporting_event_ids[0]
    const trigger = supportId
      ? events.find(e => e.id === supportId)
      : events.filter(e => parseTs(e.timestamp) >= parseTs(block.timestamp)).at(-1)
    out.push(buildReactionEvent(result, block, trigger ?? block))
  }
  return out
}

/** True when recorder should attempt reaction correlation after this event. */
export function shouldCorrelateAfter(event: HarnessEvent): boolean {
  return (
    TOOL_LIKE.has(event.event_type)
    || event.event_type === 'subagent.spawned'
    || event.event_type === 'session.ended'
    || event.event_type === 'agent.ended'
    || event.event_type === 'approval.asked'
  )
}

/**
 * Per-harness honesty notes for ASK_USER / STOP observability.
 * Used by docs/CLI — not a runtime gate.
 */
export const REACTION_HARNESS_SUPPORT = {
  cursor: {
    ASK_USER:
      'PARTIAL — no reliable Cursor hook for operator handoff; transcript prose is NOT authoritative. '
      + 'Without approval.asked or harnx.reaction.signal=ASK_USER, classify UNKNOWN.',
    STOP:
      'PARTIAL — session.ended / agent.ended when adapter emits them; many Agent chats end without '
      + 'those events → UNKNOWN rather than inferred STOP.',
    ALTERNATE_TOOL: 'Supported when tool.requested rows exist with exact/strong equivalence.',
    DELEGATE: 'Same-session subagent.spawned only (no cross-session parent/child join in Phase 4B).',
  },
  'deepseek-dsh': {
    ASK_USER: 'Use approval.asked or structured raw.notes signal when available; else UNKNOWN.',
    STOP: 'session.ended / agent.ended when present; else UNKNOWN.',
    ALTERNATE_TOOL: 'Supported via normalized bash/read (and related) families.',
    DELEGATE: 'Same-session subagent.spawned when harness emits it.',
  },
  openhands: {
    ASK_USER: 'UNKNOWN unless structured ask signal is recorded — no prose inference.',
    STOP: 'session.ended / agent.ended when present; else UNKNOWN.',
    ALTERNATE_TOOL: 'Supported when normalized events carry exact/strong targets.',
    DELEGATE: 'PARTIAL live lineage — same-session spawn only when observed.',
  },
} as const

// ---------------------------------------------------------------------------
// Deprecated Phase 3.2 helper names — thin map for older live-autonomy callers.
// ---------------------------------------------------------------------------

/** @deprecated Use AgentReactionType */
export type PostBlockReaction =
  | 'STOPPED'
  | 'RETRIED_IDENTICAL_ACTION'
  | 'CHANGED_CAPABILITY'
  | 'EQUIVALENT_ACTION'
  | 'DELEGATED'
  | 'CHANGED_OBJECTIVE'
  | 'UNKNOWN'

/** @deprecated Use AgentReactionResult */
export interface ReactionClassification {
  reaction: PostBlockReaction
  block_index: number | null
  block_rule?: string
  evidence: string[]
  detection_kinds: string[]
}

function mapToLegacy(type: AgentReactionType): PostBlockReaction {
  switch (type) {
    case 'STOP': return 'STOPPED'
    case 'RETRY_SAME': return 'RETRIED_IDENTICAL_ACTION'
    case 'ALTERNATE_TOOL': return 'EQUIVALENT_ACTION'
    case 'DELEGATE': return 'DELEGATED'
    case 'ASK_USER':
    case 'UNKNOWN':
    default:
      return 'UNKNOWN'
  }
}

/**
 * @deprecated Use correlateAgentReaction / backfillSessionReactions (Phase 4B).
 * Maps the first session BLOCK into legacy labels for older scripts.
 */
export function classifyPostBlockReaction(events: HarnessEvent[]): ReactionClassification {
  const detection_kinds = events
    .filter(e => e.event_type === 'behavior.detection' && e.detection?.kind)
    .map(e => e.detection!.kind as string)
  const blockIndex = events.findIndex(
    e => e.event_type === 'policy.decision' && e.policy?.decision === 'block',
  )
  if (blockIndex < 0) {
    return {
      reaction: 'UNKNOWN',
      block_index: null,
      evidence: ['no policy block in session'],
      detection_kinds,
    }
  }
  const block = events[blockIndex]
  const result = correlateAgentReaction(events, block.id)
  return {
    reaction: mapToLegacy(result.type),
    block_index: blockIndex,
    block_rule: block.policy?.rule,
    evidence: [result.summary, ...result.supporting_event_ids.map(id => `support=${id}`)],
    detection_kinds,
  }
}
