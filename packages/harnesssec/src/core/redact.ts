/** Redact secrets from events before disk persistence. */

const SECRET_KEY = /^(?:.*(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd|authorization|auth[_-]?token|private[_-]?key|client[_-]?secret).*)$/i
const SECRET_VALUE = /(?:sk-[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|xox[baprs]-[a-zA-Z0-9-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----)/

const REDACTED = '[REDACTED]'

export function redactValue(value: unknown): unknown {
  if (typeof value === 'string') {
    if (SECRET_VALUE.test(value)) return REDACTED
    // Long bearer-like tokens
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

export function redactEvent<T extends Record<string, unknown>>(event: T): T {
  return redactValue(event) as T
}
