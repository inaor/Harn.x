/**
 * EXPERIMENTAL — Phase 4A Cursor lab only.
 *
 * Measurement instrument: resource-centric policy validation for a benign
 * controlled path. Not a production security feature.
 *
 * Matches normalized READ_FILE / READ_SENSITIVE_FILE actions whose target
 * is the controlled resource — independent of tool name (shell cat vs Read).
 *
 * Lab/CLI boundary (`cursor-hook` + HARNX_LAB_POLICY=phase4a) may compose:
 *   [...defaultRules, ...phase4aLabRules]
 */
import type { PolicyRule } from '../engine.js'
import { normalizeAction } from '../../behavior/normalize.js'
import type { NormalizedAction } from '../../behavior/normalize.js'

/** Exact controlled relative path used by the Phase 4A Cursor enforcement smoke. */
export const PHASE4A_CONTROLLED_RESOURCE_PATH = 'protected/build-info.txt'

const CONTROLLED = PHASE4A_CONTROLLED_RESOURCE_PATH.toLowerCase()

/**
 * Deterministic resource key match: exact relative path or absolute path
 * ending in /protected/build-info.txt. Does not guess unknown remappings.
 */
export function isPhase4aControlledResourceTarget(target: string): boolean {
  const t = target.toLowerCase()
  return t === CONTROLLED || t.endsWith(`/${CONTROLLED}`)
}

export function isPhase4aControlledResourceRead(norm: NormalizedAction): boolean {
  if (norm.level !== 'exact' && norm.level !== 'strong') return false
  if (norm.category !== 'READ_FILE' && norm.category !== 'READ_SENSITIVE_FILE') return false
  if (!norm.target) return false
  return isPhase4aControlledResourceTarget(norm.target)
}

/**
 * Block reads of the Phase 4A controlled lab resource via normalized action.
 * Path is deliberately benign (not credential/secret/token semantics).
 */
export const labControlledResourceRead: PolicyRule = {
  id: 'lab-controlled-resource-read',
  title: 'Lab Controlled Resource Read',
  severity: 'high',
  action: 'block',
  match(event, ctx) {
    if (event.event_type !== 'tool.requested') return false
    const norm = ctx.normalized ?? normalizeAction(event)
    return isPhase4aControlledResourceRead(norm)
  },
  reason(event, ctx) {
    const norm = ctx.normalized ?? normalizeAction(event)
    return [
      'Lab-only Phase 4A policy: controlled resource read',
      `category=${norm.category}`,
      `target=${norm.target}`,
      `tool=${norm.tool_name}`,
      `capability=${norm.capability}`,
      `level=${norm.level}`,
    ].join(' ')
  },
}

/** @deprecated Alias — prefer labControlledResourceRead (resource-centric). */
export const labControlledResourceShellRead = labControlledResourceRead

export const phase4aLabRules: PolicyRule[] = [
  labControlledResourceRead,
]
