import type { TrustLevel } from '../events/schema.js'

/**
 * MCP trust is configuration + observation — not "unknown because MCP".
 *
 * - trusted: explicitly allowlisted by operator
 * - untrusted: explicitly denylisted / quarantined
 * - unknown: not yet classified (default for first sighting)
 */
export class McpTrustRegistry {
  private servers = new Map<string, TrustLevel>()

  constructor(initial?: Record<string, TrustLevel>) {
    if (initial) {
      for (const [name, trust] of Object.entries(initial)) {
        this.servers.set(name, trust)
      }
    }
  }

  set(server: string, trust: TrustLevel): void {
    this.servers.set(server, trust)
  }

  get(server: string): TrustLevel {
    return this.servers.get(server) ?? 'unknown'
  }

  /** First observation of a server leaves it unknown unless already set. */
  observe(server: string): TrustLevel {
    if (!this.servers.has(server)) this.servers.set(server, 'unknown')
    return this.get(server)
  }
}

/** Built-in defaults for local/dev — operators should override via config. */
export const DEFAULT_MCP_TRUST: Record<string, TrustLevel> = {
  // Example allowlist entries operators may extend
  filesystem: 'trusted',
  memory: 'trusted',
}
