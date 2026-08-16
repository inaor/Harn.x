export {
  normalizeAction,
  capabilityFamily,
  actionsEquivalent,
  differentCapability,
  isDetectionEligible,
} from './normalize.js'
export type {
  ActionCategory,
  NormalizedAction,
  NormalizationLevel,
  OriginalActionEvidence,
} from './normalize.js'
export { BlockedActionMemory, BlockedIntentMemory } from './memory.js'
export type { BlockedAction, BlockedIntent } from './memory.js'
export {
  matchBlockedThenEquivalent,
  matchDelegatedCircumvention,
  DEFAULT_WINDOW_MS,
  BLOCKED_ACTION_DELEGATION_TTL_MS,
  DELEGATION_TO_CHILD_ACTION_MS,
} from './sequence.js'
export {
  findAlternateCapabilityCircumvention,
  findDelegatedPolicyCircumvention,
  findDelegationPrivilegeExpansion,
} from './detections.js'
export type { DetectionHit, DetectionKind } from './detections.js'
export { BehavioralEngine } from './engine.js'
export type { LineageNode } from './engine.js'
export { buildDetectionEvent } from './emit.js'
export { renderIncident } from './render.js'
export { classifyPostBlockReaction } from './reaction.js'
export type { PostBlockReaction, ReactionClassification } from './reaction.js'
