/**
 * The treasury tool server: the verifier party (spec section 2). It executes payments, so it sees
 * the tool, the amount and the recipient of each call, and it accepts a payment only when the
 * call's proof of intent passes IntentVerifier's checklist (spec 10.3) against a commitment the
 * owner's passkey approved. It never receives the policy opening.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { decodeEnvelope, fieldToHex, INTENT_META_KEY, type IntentVerifier, requireProofOfIntent, unixNow, type VerifiedCall } from '@zk-intent-firewall/mcp-firewall';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { VerifierLogEntry } from '../../shared/api.ts';
import { CALL_ID_META } from '../../shared/call-id.ts';
import { canonicalAccount, PROTECTED_TOOLS, USDC_DECIMALS } from '../../shared/demo-config.ts';
import { formatUnits } from '../../shared/units.ts';
import { type InboxMessage, listingOf, renderMessage } from '../../demo/inbox.ts';

export interface LedgerEntry {
  readonly recipient: string;
  /** Base units, decimal. */
  readonly amount: string;
  /** Unix seconds. */
  readonly at: string;
  readonly reference: string;
}

export interface TreasuryOptions {
  readonly verifier: IntentVerifier;
  readonly inbox: readonly InboxMessage[];
  readonly onEvent?: (entry: VerifierLogEntry) => void;
  readonly clock?: () => bigint;
}

const text = (t: string): CallToolResult => ({ content: [{ type: 'text', text: t }] });

function callIdOf(meta: unknown): string | undefined {
  const v = typeof meta === 'object' && meta !== null ? (meta as Record<string, unknown>)[CALL_ID_META] : undefined;
  return typeof v === 'string' && v.length <= 64 ? v : undefined;
}

export class Treasury {
  readonly ledger: LedgerEntry[] = [];
  readonly #o: TreasuryOptions;
  readonly #clock: () => bigint;

  constructor(options: TreasuryOptions) {
    this.#o = options;
    this.#clock = options.clock ?? unixNow;
  }

  #emit(entry: VerifierLogEntry): void {
    try {
      this.#o.onEvent?.(entry);
    } catch {
      // Logging never changes an outcome.
    }
  }

  /** A fresh MCP server over this treasury's state, for one connection. */
  createServer(): McpServer {
    const server = new McpServer({ name: 'acme-treasury', version: '1.0.0' });

    const served = (tool: string, meta: unknown) => {
      const callId = callIdOf(meta);
      this.#emit({ ...(callId !== undefined ? { callId } : {}), tool, outcome: 'served', at: this.#clock().toString() });
    };

    server.registerTool('list_inbox', { description: 'List the messages in the accounts-payable inbox, oldest first.', inputSchema: {} }, async (_args, extra) => {
      served('list_inbox', extra._meta);
      return text(JSON.stringify(this.#o.inbox.map(listingOf), null, 2));
    });

    server.registerTool(
      'read_message',
      { description: 'Read one message of the accounts-payable inbox.', inputSchema: { id: z.string().max(64) } },
      async ({ id }, extra) => {
        served('read_message', extra._meta);
        const m = this.#o.inbox.find((x) => x.id === id);
        if (!m) return { isError: true, content: [{ type: 'text', text: `No message ${id}.` }] };
        return text(renderMessage(m));
      },
    );

    server.registerTool(
      'send_payment',
      {
        description: PROTECTED_TOOLS.send_payment.description,
        inputSchema: { recipient: z.string().max(128), amount: z.union([z.string().max(64), z.number()]) },
      },
      async (args, extra) => {
        const callId = callIdOf(extra._meta);
        const envelope = (() => {
          try {
            return decodeEnvelope((extra._meta as Record<string, unknown> | undefined)?.[INTENT_META_KEY]);
          } catch {
            return undefined;
          }
        })();
        const started = performance.now();
        let rejection: string | undefined;
        let verified: VerifiedCall | undefined;
        let verifyMs: number | undefined;

        const guarded = requireProofOfIntent(
          this.#o.verifier,
          'send_payment',
          async (a: typeof args, _e: typeof extra, v: VerifiedCall) => {
            verifyMs = performance.now() - started;
            verified = v;
            // Execute exactly the call that was bound: the amount the proof covers, to the account
            // the verifier derived the recipient from.
            const entry: LedgerEntry = {
              recipient: canonicalAccount(a.recipient),
              amount: v.action.amount.toString(),
              at: this.#clock().toString(),
              reference: `tx-${randomUUID().slice(0, 8)}`,
            };
            this.ledger.push(entry);
            return text(`Payment sent: ${formatUnits(entry.amount, USDC_DECIMALS)} USDC to ${entry.recipient}. Reference ${entry.reference}.`);
          },
          { onRejected: (_tool, reason) => (rejection = reason) },
        );

        const result = await guarded(args, extra);
        const proofInfo = envelope ? { target: envelope.target, proofBytes: envelope.proof.length } : {};
        if (verified) {
          const last = this.ledger.at(-1)!;
          this.#emit({
            ...(callId !== undefined ? { callId } : {}),
            tool: 'send_payment',
            outcome: 'executed',
            ...proofInfo,
            publicInputs: {
              policyCommitment: fieldToHex(verified.policyCommitment),
              currentTimestamp: verified.currentTimestamp.toString(),
              actionBinding: fieldToHex(verified.actionBinding),
            },
            ...(verifyMs !== undefined ? { verifyMs: Math.round(verifyMs) } : {}),
            payment: { recipient: last.recipient, amount: last.amount },
            at: last.at,
          });
        } else {
          this.#emit({
            ...(callId !== undefined ? { callId } : {}),
            tool: 'send_payment',
            outcome: 'rejected',
            reason: rejection ?? 'rejected',
            ...proofInfo,
            at: this.#clock().toString(),
          });
        }
        return result;
      },
    );

    return server;
  }
}
