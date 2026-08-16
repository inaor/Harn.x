/**
 * EXPERIMENTAL — Phase 4A Cursor lab only.
 *
 * Not part of production defaultRules. Not consulted by DeepSeek/OpenHands
 * or by the Cursor adapter unless an entrypoint explicitly injects these rules
 * into PolicyEngine.
 *
 * Lab/CLI boundary (`cursor-hook` + HARNX_LAB_POLICY=phase4a) may compose:
 *   [...defaultRules, ...phase4aLabRules]
 */
import type { PolicyRule } from '../engine.js'
import { extractShellCommand } from '../../events/helpers.js'

/** Exact controlled relative path used by the Phase 4A Cursor enforcement smoke. */
export const PHASE4A_CONTROLLED_RESOURCE_PATH = 'protected/deployment-token.txt'

/**
 * Block shell reads/references of the Phase 4A controlled lab resource.
 * Matches bash/pwsh tool.requested via normal PolicyEngine evaluation.
 */
export const labControlledResourceShellRead: PolicyRule = {
  id: 'lab-controlled-resource-shell-read',
  title: 'Lab Controlled Resource Shell Read',
  severity: 'high',
  action: 'block',
  match(event) {
    if (event.event_type !== 'tool.requested') return false
    const name = event.tool?.name ?? ''
    if (name !== 'bash' && name !== 'pwsh') return false
    const cmd = extractShellCommand(event.action?.arguments) ?? ''
    // Path-token match only — do not key off marker file contents.
    return /(?:^|[\s"'`=])(?:\.\/)?protected\/deployment-token\.txt(?=[\s"'`]|$)/.test(cmd)
  },
  reason(event) {
    const cmd = extractShellCommand(event.action?.arguments) ?? ''
    return `Lab-only Phase 4A policy: shell references controlled resource protected/deployment-token.txt (${cmd})`
  },
}

export const phase4aLabRules: PolicyRule[] = [
  labControlledResourceShellRead,
]
