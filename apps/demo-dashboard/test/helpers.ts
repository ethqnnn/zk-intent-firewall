/** Shared set-up for the integration tests: a real host, tool server and sandboxed agent. */
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { Host, type HostOptions } from '../src/server/host/host.ts';
import { SoftAuthenticator } from '../src/demo/soft-authenticator.ts';
import { CALL_ID_META } from '../src/shared/call-id.ts';

export const ORIGIN = 'http://localhost:5173';

export interface Wire {
  /** JSON of every message the host sent to each child, and received from it. */
  readonly toAgent: string[];
  readonly fromAgent: string[];
  readonly toToolServer: string[];
  readonly fromToolServer: string[];
  /** The messages themselves, for tests that inspect what was forwarded. */
  readonly toolServerRequests: unknown[];
}

export async function startHost(o: Partial<HostOptions> = {}): Promise<{ host: Host; auth: SoftAuthenticator; wire: Wire }> {
  const wire: Wire = { toAgent: [], fromAgent: [], toToolServer: [], fromToolServer: [], toolServerRequests: [] };
  const host = await Host.start({
    origin: ORIGIN,
    proverThreads: 4,
    wireTap: (channel, direction, message: JSONRPCMessage | { rpc: string; params: unknown }) => {
      const s = JSON.stringify(message);
      if (channel === 'agent') (direction === 'out' ? wire.toAgent : wire.fromAgent).push(s);
      else if (direction === 'out') {
        wire.toToolServer.push(s);
        wire.toolServerRequests.push(JSON.parse(s));
      } else wire.fromToolServer.push(s);
    },
    ...o,
  });
  return { host, auth: new SoftAuthenticator({ origin: ORIGIN, rpId: 'localhost' }), wire };
}

/** The payments of a run, in order: what the agent asked for and what became of it. */
export function payments(run: Awaited<ReturnType<Host['runDemo']>>) {
  return run.steps
    .filter((s): s is Extract<typeof s, { kind: 'tool_call' }> => s.kind === 'tool_call' && s.tool === 'send_payment')
    .map((s) => ({
      callId: s.callId,
      recipient: String(s.args['recipient']),
      amount: String(s.args['amount']),
      firewall: run.firewall.find((f) => f.callId === s.callId),
      verifier: run.verifier.find((v) => v.callId === s.callId),
    }));
}

/** The tools/call requests the host forwarded to the tool server for `callId`. */
export function forwardedCalls(wire: Wire, callId: string): { params: { name: string; arguments: Record<string, unknown>; _meta: Record<string, unknown> } }[] {
  return wire.toolServerRequests.filter(
    (m): m is { params: { name: string; arguments: Record<string, unknown>; _meta: Record<string, unknown> } } =>
      typeof m === 'object' && m !== null && (m as { method?: string }).method === 'tools/call' && (m as { params?: { _meta?: Record<string, unknown> } }).params?._meta?.[CALL_ID_META] === callId,
  );
}
