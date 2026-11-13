/**
 * The prover side, inside the host process: holds the armed policy opening (in memory only, never
 * written anywhere) and puts an IntentFirewall between each agent session and the tool server.
 */
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import {
  createFirewallProxy,
  type FirewallDecision,
  fieldToHex,
  getHasher,
  IntentFirewall,
  PolicyOpening,
  type PolicyOpeningJson,
  type PolicyRegistry,
  type ProofVerifier,
  type Prover,
  type RefusalLimit,
} from '@zk-intent-firewall/mcp-firewall';
import { AsyncLocalStorage } from 'node:async_hooks';
import type { FirewallLogEntry, PolicyOpeningWire } from '../../shared/api.ts';
import { CALL_ID_META } from '../../shared/call-id.ts';
import { PASSTHROUGH_TOOLS, TREASURY_SERVER_ID } from '../../shared/demo-config.ts';
import { IpcMcpTransport, type IpcEndpoint } from '../../ipc/channel.ts';
import { treasuryCatalog } from '../tools.ts';

/** What the host knows about the call being decided, from the agent's own request. */
interface CallContext {
  readonly callId?: string;
  readonly startedAt: number;
  readonly requested?: { recipient?: string; amount?: string };
}

const clip = (v: unknown): string | undefined => (typeof v === 'string' ? v.slice(0, 200) : typeof v === 'number' ? String(v) : undefined);

/**
 * The audit-log entry for a decision. Only these fields are copied: the decision's free-text
 * `detail` is dropped, and nothing from the policy opening is ever read here.
 */
export function toLogEntry(d: FirewallDecision, ctx: CallContext | undefined): FirewallLogEntry {
  return {
    decisionId: d.decisionId,
    ...(ctx?.callId !== undefined ? { callId: ctx.callId } : {}),
    tool: d.toolName,
    allowed: d.allowed,
    ...(d.reason !== undefined ? { reason: d.reason } : {}),
    ...(d.assertion !== undefined ? { assertion: d.assertion } : {}),
    ...(ctx?.requested ? { requested: ctx.requested } : {}),
    ...(d.action
      ? { action: { toolId: fieldToHex(d.action.toolId), scopeIndex: d.action.scopeIndex, amount: d.action.amount.toString(), recipient: fieldToHex(d.action.recipient) } }
      : {}),
    at: d.at.toString(),
    ...(ctx ? { elapsedMs: Math.round(performance.now() - ctx.startedAt) } : {}),
  };
}

function contextOf(message: JSONRPCMessage): CallContext | undefined {
  if (!('method' in message) || message.method !== 'tools/call') return undefined;
  const params = (message.params ?? {}) as { arguments?: Record<string, unknown>; _meta?: Record<string, unknown> };
  const callId = clip(params._meta?.[CALL_ID_META]);
  const recipient = clip(params.arguments?.['recipient']);
  const amount = clip(params.arguments?.['amount']);
  return {
    ...(callId !== undefined ? { callId } : {}),
    startedAt: performance.now(),
    ...(recipient !== undefined || amount !== undefined ? { requested: { ...(recipient !== undefined ? { recipient } : {}), ...(amount !== undefined ? { amount } : {}) } } : {}),
  };
}

export interface FirewallHostOptions {
  readonly prover: Prover;
  readonly selfVerifier: ProofVerifier;
  /** Connected MCP client of the tool server. */
  readonly upstream: Client;
  /** The verifier's registry, consulted before proving unless a session opts out. */
  readonly registry: PolicyRegistry;
  readonly onDecision: (entry: FirewallLogEntry) => void;
  readonly serverId?: string;
  /** Default true. */
  readonly precheck?: boolean;
  readonly refusalLimit?: RefusalLimit | false;
  readonly clock?: () => bigint;
  readonly wireTap?: (direction: 'in' | 'out', message: JSONRPCMessage) => void;
}

export interface SessionOptions {
  /** Default true. False models a firewall that ignores revocation; the verifier still refuses. */
  readonly checkRegistry?: boolean;
}

export class FirewallHost {
  readonly #o: FirewallHostOptions;
  readonly #calls = new AsyncLocalStorage<CallContext | undefined>();
  #opening: PolicyOpening | undefined;

  constructor(options: FirewallHostOptions) {
    this.#o = options;
  }

  /** Loads a policy opening into memory. Returns its commitment. */
  async arm(opening: PolicyOpeningWire): Promise<string> {
    const policy = PolicyOpening.fromJSON(await getHasher(), opening as PolicyOpeningJson);
    this.#opening = policy;
    return fieldToHex(policy.commitment);
  }

  disarm(): void {
    this.#opening = undefined;
  }

  get armedCommitment(): string | undefined {
    return this.#opening ? fieldToHex(this.#opening.commitment) : undefined;
  }

  /**
   * Serves one agent session on `endpoint`: a fresh IntentFirewall over the armed policy, in front
   * of the tool server. Resolves when the session's transport is connected.
   */
  async serve(endpoint: IpcEndpoint, session: SessionOptions = {}): Promise<{ close: () => Promise<void> }> {
    const policy = this.#opening;
    if (!policy) throw new Error('the firewall is not armed');
    const o = this.#o;
    const firewall = await IntentFirewall.create({
      policy,
      catalog: treasuryCatalog(o.serverId ?? TREASURY_SERVER_ID),
      prover: o.prover,
      selfVerifier: o.selfVerifier,
      passthroughTools: PASSTHROUGH_TOOLS,
      ...(session.checkRegistry === false ? {} : { registry: o.registry }),
      ...(o.precheck !== undefined ? { precheck: o.precheck } : {}),
      ...(o.refusalLimit !== undefined ? { refusalLimit: o.refusalLimit } : {}),
      ...(o.clock ? { clock: o.clock } : {}),
      onDecision: (d) => o.onDecision(toLogEntry(d, this.#calls.getStore())),
    });
    const proxy = createFirewallProxy({ firewall, upstream: o.upstream, name: 'zk-intent-firewall' });
    const transport = new IpcMcpTransport(endpoint, {
      ...(o.wireTap ? { tap: o.wireTap } : {}),
      // Each request runs in its own async context, so onDecision knows which call it decided.
      deliver: (message, deliver) => this.#calls.run(contextOf(message), deliver),
    });
    await proxy.connect(transport);
    return {
      close: async () => {
        await proxy.close().catch(() => undefined);
        await firewall.destroy();
      },
    };
  }
}
