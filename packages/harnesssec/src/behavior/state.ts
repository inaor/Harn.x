import type { BlockedAction } from './memory.js'
import type { DetectionKind } from './detections.js'

/** Per-session behavioral view (in-memory summary). */
export interface SessionBehaviorState {
  session_id: string
  blocked: BlockedAction[]
  detections: Array<{ kind: DetectionKind; event_id: string; title: string }>
}
