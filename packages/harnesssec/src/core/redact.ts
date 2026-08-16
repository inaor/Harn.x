/** Redact secrets from a clone before disk persistence. Never mutate the input. */

const SECRET_KEY = /(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|authorization|auth[_-]?token|private[_-]?key|client[_-]?secret|aws[_-]?secret|secret[_-]?access[_-]?key)/i

const SECRET_VALUE = /(?:sk-[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)/

const REDACTED = '[REDACTED]'

export function redactValue(value: unknown): unknown {
  if (typeof value === 'string') {
    if (SECRET_VALUE.test(value)) return REDACTED
    if (/^Bearer\s+\S{12,}/i.test(value)) return 'Bearer [REDACTED]'
    return value
  }
  if (Array.isArray(value)) return value.map(redactValue)
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY.test(k)) {
        out[k] = REDACTED
      } else {
        out[k] = redactValue(v)
      }
    }
    return out
  }
  return value
}

/** Returns a redacted deep clone. Input is never mutated. */
export function redactEvent<T>(event: T): T {
  const clone = typeof structuredClone === 'function'
    ? structuredClone(event)
    : JSON.parse(JSON.stringify(event)) as T
  return redactValue(clone) as T
}
