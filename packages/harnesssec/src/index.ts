import { FlightRecorder } from './core/recorder.js'
import { PolicyEngine } from './policy/engine.js'
import { defaultRules } from './policy/rules.js'
import {
  apply,
  createRuntime,
  name,
  inject,
  Config,
} from './adapters/deepseek/index.js'

export type { HarnessEvent, EventType, TrustLevel } from './events/schema.js'
export { FlightRecorder } from './core/recorder.js'
export { PolicyEngine } from './policy/engine.js'
export { defaultRules } from './policy/rules.js'
export { CausalGraph } from './graph/causal.js'
export { createRuntime }

/** Cordis plugin entry — `dsh plugin add` loads these from package root. */
export { apply, name, inject, Config }
export default { name, inject, apply, Config }

export function createHarnessSec(storeDir: string): { recorder: FlightRecorder; policy: PolicyEngine } {
  const recorder = new FlightRecorder(storeDir)
  const policy = new PolicyEngine(recorder, defaultRules)
  return { recorder, policy }
}
