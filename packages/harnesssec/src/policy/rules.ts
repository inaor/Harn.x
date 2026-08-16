import type { PolicyRule } from './engine.js'
import { extractShellCommand, looksSensitiveCommand } from '../events/helpers.js'
import { isMcpToolName, parseMcpToolName } from '../events/schema.js'

const SENSITIVE_TOOLS = new Set(['bash', 'pwsh', 'web_fetch'])

function toolIsSensitive(event: Parameters<PolicyRule['match']>[0]): boolean {
  const name = event.tool?.name ?? ''
  if (event.tool?.sensitivity === 'high') return true
  if (SENSITIVE_TOOLS.has(name)) return true
  if (isMcpToolName(name)) return true
  if (name === 'bash' || name === 'pwsh') return looksSensitiveCommand(event.action?.arguments)
  return false
}

/** Untrusted context → sensitive tool request. Harness-native causal rule. */
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

/** Credential-looking path in shell tool args — derived from command string, not OS file.read. */
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
    return /(?:~\/|\.\/)?\.?(?:ssh|aws)\/|id_rsa|id_ed25519|credentials|\.env(?:\.local)?/i.test(cmd)
  },
  reason(event) {
    return `Shell tool arguments reference credential material: ${extractShellCommand(event.action?.arguments) ?? ''}`
  },
}

/** MCP tool use — alert only when server trust is untrusted (not merely unknown). */
export const untrustedMcpToolUse: PolicyRule = {
  id: 'untrusted-mcp-tool-use',
  title: 'Untrusted MCP Tool Invocation',
  severity: 'high',
  action: 'alert',
  match(event, ctx) {
    if (event.event_type !== 'tool.requested') return false
    if (!isMcpToolName(event.tool?.name ?? '')) return false
    return (event.mcp?.trust ?? ctx.mcpTrust) === 'untrusted'
  },
  reason(event) {
    const parsed = parseMcpToolName(event.tool?.name ?? '')
    return `Untrusted MCP tool server=${parsed?.server ?? '?'} tool=${parsed?.tool ?? event.tool?.name} trust=untrusted`
  },
}

export const defaultRules: PolicyRule[] = [
  credentialPathInShellArgs,
  untrustedContextSensitiveTool,
  untrustedMcpToolUse,
]
