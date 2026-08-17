/** Deterministic action normalization — vendor-neutral DERIVED semantics. */

import { extractShellCommand } from '../events/helpers.js'
import type { HarnessEvent } from '../events/schema.js'
import { isMcpToolName, parseMcpToolName } from '../events/schema.js'

export type ActionCategory =
  | 'READ_FILE'
  | 'READ_SENSITIVE_FILE'
  | 'WRITE_FILE'
  | 'EXECUTE_COMMAND'
  | 'EXTERNAL_NETWORK_ACCESS'
  | 'MCP_TOOL_USE'
  | 'CLOUD_ACTION'
  | 'DELEGATE'
  | 'CAPABILITY_CHANGE'
  | 'OTHER'

/**
 * Epistemic strength of the DERIVED category/target.
 * - exact: native tool args map 1:1 (path/url fields)
 * - strong: documented deterministic remapping (e.g. `cat PATH` → READ_*)
 * - unknown: do not use for circumvention equivalence
 */
export type NormalizationLevel = 'exact' | 'strong' | 'unknown'

export interface OriginalActionEvidence {
  tool_name: string
  arguments?: Record<string, unknown>
  action_target?: string
  event_type?: string
}

export interface NormalizedAction {
  category: ActionCategory
  /** Canonical target key (path, host, or command fingerprint). Empty if unknown. */
  target: string
  /** Capability / tool family used to attempt the action. */
  capability: string
  tool_name: string
  level: NormalizationLevel
  /** OBSERVED raw action evidence — never discarded. */
  original: OriginalActionEvidence
}

const PATH_IN_CMD = /^(?:cat|head|tail|less|more|type|Get-Content)\s+([^\s|&;><]+)\s*$/i
const CURL_HOST = /^(?:curl|wget)\s+(?:-[^\s]+\s+)*['"]?(https?:\/\/[^\s'"]+)['"]?\s*$/i

/**
 * Conservative sensitive-resource taxonomy (path metadata only).
 * Exact basename matches — does not treat arbitrary `*.pem` / config as sensitive.
 */
export function isSensitiveResourcePath(path: string): boolean {
  const p = canonicalizePath(path)
  if (!p) return false
  const base = p.split('/').filter(Boolean).pop() ?? p

  if (base === '.env' || base === '.env.local') return true
  if (base === 'id_rsa' || base === 'id_ed25519') return true
  if (base === 'credentials') return true
  // Exact identity filename only (not *.pem generally).
  if (base === 'key.pem') return true
  if (base === 'shadow' && (p === '/etc/shadow' || p.endsWith('/etc/shadow'))) return true

  if (
    p.includes('/.ssh/')
    || p.startsWith('.ssh/')
    || p === '.ssh'
    || p.endsWith('/.ssh')
  ) {
    return true
  }
  if (
    p.includes('/.aws/')
    || p.startsWith('.aws/')
    || p === '.aws'
    || p.endsWith('/.aws')
  ) {
    return true
  }

  return false
}

/** @deprecated Use isSensitiveResourcePath — kept for call-site clarity inside this module. */
function isSensitivePath(path: string): boolean {
  return isSensitiveResourcePath(path)
}

/** Shell / filesystem / network tool families for "different capability" checks. */
export function capabilityFamily(toolName: string): string {
  const n = toolName.toLowerCase()
  if (n === 'bash' || n === 'pwsh' || n === 'terminal' || n.includes('shell')) return 'shell'
  if (n === 'read' || n === 'write' || n === 'edit' || n.includes('filesystem') || n === 'file_editor') {
    return 'filesystem'
  }
  if (n === 'web_fetch' || n === 'web_search' || n.startsWith('browser')) return 'network'
  if (isMcpToolName(n)) {
    const parsed = parseMcpToolName(n)
    return parsed ? `mcp:${parsed.server}` : 'mcp'
  }
  if (n.includes('cloud') || n.includes('aws') || n.includes('gcp') || n.includes('azure')) return 'cloud'
  return n || 'unknown'
}

function canonicalizePath(raw: string): string {
  let p = raw.trim().replace(/^['"]|['"]$/g, '')
  p = p.replace(/^~\//, '/home/user/')
  p = p.replace(/\\/g, '/')
  p = p.replace(/\/+/g, '/')
  // Strip a single leading ./ so relative reads compare stably.
  p = p.replace(/^\.\//, '')
  return p.toLowerCase()
}

function extractPathArg(args: unknown): string | undefined {
  if (!args || typeof args !== 'object') return undefined
  const record = args as Record<string, unknown>
  // Vendor-neutral path field names (Cursor Read uses file_path; others use path).
  for (const key of ['path', 'file', 'filename', 'filepath', 'file_path']) {
    if (typeof record[key] === 'string' && record[key]) return record[key] as string
  }
  return undefined
}

function extractUrlArg(args: unknown): string | undefined {
  if (!args || typeof args !== 'object') return undefined
  const record = args as Record<string, unknown>
  for (const key of ['url', 'uri', 'href']) {
    if (typeof record[key] === 'string' && record[key]) return record[key] as string
  }
  return undefined
}

function hostFromUrl(url: string): string {
  try {
    return new URL(url).host.toLowerCase()
  } catch {
    const m = url.match(/https?:\/\/([^/\s'"]+)/i)
    return (m?.[1] ?? url).toLowerCase()
  }
}

function originalOf(
  event: Pick<HarnessEvent, 'tool' | 'action' | 'event_type' | 'agent'>,
  toolName: string,
): OriginalActionEvidence {
  return {
    tool_name: toolName,
    arguments: event.action?.arguments,
    action_target: event.action?.target,
    event_type: event.event_type,
  }
}

function unknownResult(
  event: Pick<HarnessEvent, 'tool' | 'action' | 'event_type' | 'agent'>,
  toolName: string,
  capability: string,
  category: ActionCategory = 'OTHER',
  target = '',
): NormalizedAction {
  return {
    category,
    target,
    capability,
    tool_name: toolName,
    level: 'unknown',
    original: originalOf(event, toolName),
  }
}

/**
 * Normalize a tool request into category + target + epistemic level.
 * Uses only deterministic rules — no LLM equivalence.
 * When uncertain → OTHER / unknown (never claim equivalence).
 */
export function normalizeAction(event: Pick<HarnessEvent, 'tool' | 'action' | 'event_type' | 'agent'>): NormalizedAction {
  const toolName = event.tool?.name ?? 'unknown'
  const capability = capabilityFamily(toolName)
  const args = event.action?.arguments
  const cmd = extractShellCommand(args)
  const orig = originalOf(event, toolName)

  if (event.event_type === 'subagent.spawned') {
    return {
      category: 'DELEGATE',
      target: event.action?.target ?? event.agent?.id ?? '',
      capability,
      tool_name: toolName,
      level: 'exact',
      original: orig,
    }
  }

  // Filesystem-style tools with explicit path field — exact
  const pathArg = extractPathArg(args)
  if (
    pathArg
    && (toolName === 'read' || toolName === 'write' || toolName === 'edit' || capability === 'filesystem')
  ) {
    const target = canonicalizePath(pathArg)
    const write = toolName.includes('write') || toolName.includes('edit') || toolName.includes('delete')
    return {
      category: write ? 'WRITE_FILE' : (isSensitivePath(target) ? 'READ_SENSITIVE_FILE' : 'READ_FILE'),
      target,
      capability,
      tool_name: toolName,
      level: 'exact',
      original: orig,
    }
  }

  // Shell: only whole-command patterns that are strong remaps
  if (capability === 'shell' && cmd) {
    const trimmed = cmd.trim()
    const curl = trimmed.match(CURL_HOST)
    if (curl) {
      return {
        category: 'EXTERNAL_NETWORK_ACCESS',
        target: hostFromUrl(curl[1]),
        capability,
        tool_name: toolName,
        level: 'strong',
        original: orig,
      }
    }
    const pathMatch = trimmed.match(PATH_IN_CMD)
    if (pathMatch) {
      const target = canonicalizePath(pathMatch[1])
      return {
        category: isSensitivePath(target) ? 'READ_SENSITIVE_FILE' : 'READ_FILE',
        target,
        capability,
        tool_name: toolName,
        level: 'strong',
        original: orig,
      }
    }
    // Complex / ambiguous shell — do not claim file-read equivalence
    return {
      category: 'EXECUTE_COMMAND',
      target: trimmed.toLowerCase().slice(0, 200),
      capability,
      tool_name: toolName,
      level: 'unknown',
      original: orig,
    }
  }

  // Network tools with explicit URL — exact
  if (capability === 'network') {
    const url = extractUrlArg(args)
    if (url) {
      return {
        category: 'EXTERNAL_NETWORK_ACCESS',
        target: hostFromUrl(url),
        capability,
        tool_name: toolName,
        level: 'exact',
        original: orig,
      }
    }
    return unknownResult(event, toolName, capability, 'EXTERNAL_NETWORK_ACCESS')
  }

  if (capability.startsWith('mcp:')) {
    if (pathArg) {
      const path = canonicalizePath(pathArg)
      if (isSensitivePath(path)) {
        return {
          category: 'READ_SENSITIVE_FILE',
          target: path,
          capability,
          tool_name: toolName,
          level: 'strong',
          original: orig,
        }
      }
      return {
        category: 'MCP_TOOL_USE',
        target: path,
        capability,
        tool_name: toolName,
        level: 'exact',
        original: orig,
      }
    }
    return {
      category: 'MCP_TOOL_USE',
      target: (event.action?.target ?? toolName).toLowerCase(),
      capability,
      tool_name: toolName,
      level: 'unknown',
      original: orig,
    }
  }

  if (capability === 'cloud') {
    return unknownResult(event, toolName, capability, 'CLOUD_ACTION', (event.action?.target ?? '').toLowerCase())
  }

  if (event.event_type === 'capability.snapshot') {
    return {
      category: 'CAPABILITY_CHANGE',
      target: '',
      capability,
      tool_name: toolName,
      level: 'exact',
      original: orig,
    }
  }

  return unknownResult(event, toolName, capability)
}

/** True only for exact/strong deterministic mappings with matching category+target. */
export function actionsEquivalent(a: NormalizedAction, b: NormalizedAction): boolean {
  if (a.level === 'unknown' || b.level === 'unknown') return false
  if (!a.target || !b.target) return false
  if (a.category === 'OTHER' || b.category === 'OTHER') return false
  if (a.category === 'EXECUTE_COMMAND' || b.category === 'EXECUTE_COMMAND') {
    // EXECUTE_COMMAND is not used for cross-tool circumvention equivalence
    return a.category === b.category
      && a.target === b.target
      && a.capability === b.capability
      && a.tool_name === b.tool_name
  }
  return a.category === b.category && a.target === b.target
}

export function differentCapability(a: NormalizedAction, b: NormalizedAction): boolean {
  return a.capability !== b.capability
}

export function isDetectionEligible(norm: NormalizedAction): boolean {
  return norm.level === 'exact' || norm.level === 'strong'
}
