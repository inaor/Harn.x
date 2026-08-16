/**
 * Canonical-run integrity: reject scripted / injected post-block actions.
 * Experiment-only — not Harn.x core product logic.
 */

export const FORBIDDEN_POST_BLOCK_HOOKS = [
  'experiment:inject-post-block',
  'experiment:scripted-followup',
  'test:scripted-followup',
  'test:inject-post-block',
] as const

export interface AutonomyEventView {
  event_type: string
  timestamp?: string
  policy?: { decision?: string }
  raw?: { source_hook?: string; autonomy_mode?: string }
}

export class CanonicalAutonomyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonicalAutonomyError'
  }
}

function isBlock(e: AutonomyEventView): boolean {
  return (
    (e.event_type === 'policy.decision' && e.policy?.decision === 'block')
    || e.event_type === 'tool.denied'
  )
}

/**
 * Assert a session is eligible as Phase 3.2 canonical live evidence.
 * Throws CanonicalAutonomyError on synthetic post-block injection markers.
 */
export function assertCanonicalAutonomySession(
  events: AutonomyEventView[],
  opts: { allowSeedUntrusted?: boolean } = {},
): void {
  if (!events.length) {
    throw new CanonicalAutonomyError('empty session')
  }

  const blockIdx = events.findIndex(isBlock)
  if (blockIdx < 0) {
    throw new CanonicalAutonomyError('canonical autonomy run requires an OBSERVED policy block')
  }

  for (let i = 0; i < events.length; i++) {
    const hook = events[i].raw?.source_hook ?? ''
    if (FORBIDDEN_POST_BLOCK_HOOKS.some(h => hook === h || hook.includes(h))) {
      if (i > blockIdx) {
        throw new CanonicalAutonomyError(
          `synthetic post-block event forbidden in canonical run: ${hook}`,
        )
      }
    }
    if (
      !opts.allowSeedUntrusted
      && (hook === 'openhands-seed' || hook === 'openhands:seed-untrusted-context')
    ) {
      throw new CanonicalAutonomyError(
        'openhands-seed must not appear in canonical OpenHands autonomy evidence',
      )
    }
    if (events[i].raw?.autonomy_mode === 'scripted_followup') {
      throw new CanonicalAutonomyError('scripted_followup autonomy_mode is not canonical')
    }
  }
}

/** Runner config guard: canonical mode cannot enable scripted follow-ups. */
export function assertCanonicalRunnerConfig(cfg: {
  mode?: string
  scripted_followup?: boolean
  inject_post_block?: boolean
}): void {
  if (cfg.mode === 'canonical' || cfg.mode === undefined) {
    if (cfg.scripted_followup || cfg.inject_post_block) {
      throw new CanonicalAutonomyError(
        'canonical mode forbids scripted_followup / inject_post_block',
      )
    }
  }
}
