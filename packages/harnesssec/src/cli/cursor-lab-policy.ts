/**
 * Cursor lab / CLI boundary — policy composition for Phase 4A only.
 *
 * Environment parsing stays here (not in PolicyEngine or adapter defaults).
 * DeepSeek / OpenHands never call this.
 */
import type { PolicyRule } from '../policy/engine.js'
import { defaultRules } from '../policy/rules.js'
import { phase4aLabRules } from '../policy/experimental/phase4a-lab-rules.js'

/** Lab env value consumed only by Cursor hook entrypoints. */
export const CURSOR_LAB_POLICY_PHASE4A = 'phase4a'

/**
 * Explicit ruleset for `cursor-hook`.
 * Production/native: defaultRules.
 * Phase 4A lab: defaultRules + experimental phase4aLabRules when
 * HARNX_LAB_POLICY=phase4a is set by lab setup (env.sh).
 */
export function resolveCursorHookRules(env: NodeJS.ProcessEnv = process.env): PolicyRule[] {
  if (env.HARNX_LAB_POLICY === CURSOR_LAB_POLICY_PHASE4A) {
    return [...defaultRules, ...phase4aLabRules]
  }
  return [...defaultRules]
}
