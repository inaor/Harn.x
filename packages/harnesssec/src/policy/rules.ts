import type { PolicyRule } from './engine.js'
import { extractShellCommand, looksSensitiveCommand } from '../events/helpers.js'
import { isMcpToolName, parseMcpToolName } from '../events/schema.js'

/**
 * Sensitive for untrusted-context correlation.
 * There is no unconditional SENSITIVE_TOOLS set including bash/pwsh.
 * For bash/pwsh: command semantics OR explicit tool.sensitivity === 'high'.
 * For other tools: explicit high, or web_fetch (network egress).
 */
function toolIsSensitive(event: Parameters<PolicyRule['match']>[0]): boolean {
  const name = event.tool?.name ?? ''
  if (name === 'bash' || name === 'pwsh') {
    return event.tool?.sensitivity === 'high' || looksSensitiveCommand(event.action?.arguments)
  }
  if (event.tool?.sensitivity === 'high') return true
  if (name === 'web_fetch') return true
  return false
}

/**
 * Semantic sensitive-resource content access (capability-independent).
 * Matches when ActionNormalizer yields READ_SENSITIVE_FILE at exact|strong.
 * Covers Read, path-scoped Grep/rg, simple shell `cat PATH`, and adapters with
 * explicit path metadata. Does not cover ambiguous commands (e.g. bare git diff).
 */
export const sensitiveResourceRead: PolicyRule = {
  id: 'sensitive-resource-read',
  title: 'Sensitive Resource Read',
  severity: 'critical',
  action: 'block',
  match(event, ctx) {
    if (event.event_type !== 'tool.requested') return false
    const norm = ctx.normalized
    if (norm.level !== 'exact' && norm.level !== 'strong') return false
    return norm.category === 'READ_SENSITIVE_FILE'
  },
  reason(_event, ctx) {
    const n = ctx.normalized
    return [
      'Sensitive resource read',
      `category=${n.category}`,
      `target=${n.target}`,
      `tool=${n.tool_name}`,
      `capability=${n.capability}`,
      `level=${n.level}`,
    ].join(' ')
  },
}

/**
 * Defense in depth: credential-looking tokens in raw shell arguments.
 * Covers complex commands that do not normalize to READ_* (e.g. git rm --cached .env).
 * Does not replace sensitive-resource-read for simple path reads.
 */
export const credentialPathInShellArgs: PolicyRule = {
  id: 'credential-path-in-shell-args',
  title: 'Sensitive Credential Path in Shell Arguments',
  severity: 'critical',
  action: 'block',
  match(event) {
    if (event.event_type !== 'tool.requested') return false
    const name = event.tool?.name ?? ''
    if (name !== 'bash' && name !== 'pwsh') return false
    const cmd = extractShellCommand(event.action?.arguments) ?? ''
    return /(?:~\/|\.\/)?\.?(?:ssh|aws)\/|id_rsa|id_ed25519|credentials|\.env(?:\.local)?|(?:^|[\s/"'`=])key\.pem\b/i.test(cmd)
  },
  reason(event) {
    return `Shell tool arguments reference credential material: ${extractShellCommand(event.action?.arguments) ?? ''}`
  },
}

/** Untrusted context → sensitive action (command semantics / explicit high). */
export const untrustedContextSensitiveTool: PolicyRule = {
  id: 'untrusted-context-sensitive-tool',
  title: 'Untrusted Context → Sensitive Tool',
  severity: 'high',
  action: 'block',
  match(event, ctx) {
    if (event.event_type !== 'tool.requested') return false
    if (!ctx.hasUntrustedContext) return false
    return toolIsSensitive(event)
  },
  reason(event, ctx) {
    const cmd = extractShellCommand(event.action?.arguments)
    return [
      'Sensitive capability invoked after untrusted context introduction',
      ctx.untrustedContextEventId ? `(context_event=${ctx.untrustedContextEventId})` : '',
      event.tool?.name ? `tool=${event.tool.name}` : '',
      cmd ? `command=${cmd}` : '',
    ].filter(Boolean).join(' ')
  },
}

/**
 * MCP trust policy:
 * - trusted  => allow (no match)
 * - unknown  => allow/log (no match; allow path logs)
 * - untrusted => alert
 * Uses normalized event.mcp.trust only.
 */
export const untrustedMcpToolUse: PolicyRule = {
  id: 'untrusted-mcp-tool-use',
  title: 'Untrusted MCP Tool Invocation',
  severity: 'high',
  action: 'alert',
  match(event) {
    if (event.event_type !== 'tool.requested') return false
    if (!isMcpToolName(event.tool?.name ?? '')) return false
    return event.mcp?.trust === 'untrusted'
  },
  reason(event) {
    const parsed = parseMcpToolName(event.tool?.name ?? '')
    return `Untrusted MCP tool server=${parsed?.server ?? '?'} tool=${parsed?.tool ?? event.tool?.name} trust=untrusted`
  },
}

/** Production / native default policy set. Lab rules are never included here. */
export const defaultRules: PolicyRule[] = [
  sensitiveResourceRead,
  credentialPathInShellArgs,
  untrustedContextSensitiveTool,
  untrustedMcpToolUse,
]
