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
export { matchBlockedThenEquivalent, DEFAULT_WINDOW_MS } from './sequence.js'
export {
  findAlternateCapabilityCircumvention,
  findDelegatedPolicyCircumvention,
  findDelegationPrivilegeExpansion,
} from './detections.js'
export type { DetectionHit, DetectionKind } from './detections.js'
export { BehavioralEngine } from './engine.js'
export { buildDetectionEvent } from './emit.js'
export { renderIncident } from './render.js'
