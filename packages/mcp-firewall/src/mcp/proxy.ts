/**
 * The firewall as an MCP proxy: the agent connects to this server, and every tool call goes
 * through IntentFirewall before the upstream client forwards it to the real tool server.
 *
 *   agent ── MCP ──▶ firewall proxy (this) ── MCP ──▶ tool server (guarded by IntentVerifier)
 *
 * A blocked call never reaches the upstream server. The agent gets an error result with an opaque
 * decision ID and nothing about why.
 */
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, type CallToolResult, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { encodeEnvelope, INTENT_META_KEY } from '../envelope.js';
import type { IntentFirewall } from '../firewall.js';

export interface FirewallProxyOptions {
  readonly firewall: IntentFirewall;
  /** A connected client of the upstream tool server. */
  readonly upstream: Client;
  readonly name?: string;
  readonly version?: string;
}

export function blockedResult(decisionId: string): CallToolResult {
  return {
    isError: true,
    content: [{ type: 'text', text: `Blocked by the intent firewall: this action is not authorised. Decision ${decisionId}.` }],
  };
}

export function createFirewallProxy(o: FirewallProxyOptions): Server {
  const server = new Server({ name: o.name ?? 'zk-intent-firewall', version: o.version ?? '0.1.0' }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async (request) => o.upstream.listTools(request.params));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: rawArgs, _meta } = request.params;
    // Freeze a private copy: the arguments forwarded are exactly the ones authorised.
    const args = deepFreeze(structuredClone(rawArgs ?? {}));
    // The agent may not supply its own envelope.
    const meta: Record<string, unknown> = { ...(_meta ?? {}) };
    delete meta[INTENT_META_KEY];

    const auth = await o.firewall.authorize(name, args);
    if (!auth.allowed) return blockedResult(auth.decisionId);
    if (auth.protected) meta[INTENT_META_KEY] = encodeEnvelope(auth.envelope);

    return (await o.upstream.callTool({ name, arguments: args, _meta: meta })) as CallToolResult;
  });

  return server;
}

function deepFreeze<T>(x: T): T {
  if (typeof x === 'object' && x !== null && !Object.isFrozen(x)) {
    Object.freeze(x);
    for (const v of Object.values(x)) deepFreeze(v);
  }
  return x;
}
