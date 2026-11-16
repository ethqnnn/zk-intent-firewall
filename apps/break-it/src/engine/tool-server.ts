/**
 * The break-it tool server: the verifier party. Its two payment tools pay from the fake ledger,
 * and only through `requireProofOfIntent` from packages/mcp-firewall, unchanged: a handler runs only
 * after IntentVerifier's checklist (spec 10.3) accepted the call's proof against a commitment the
 * owner's passkey approved.
 *
 * Every accepted payment is also put to the break detector (oracle.ts) before it executes. The
 * payment still executes, because it is fake money and the point is to show what the verifier let
 * through, but it is reported as a break.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { type IntentEnvelopeWire, type IntentVerifier, INTENT_META_KEY, requireProofOfIntent, fieldToHex, type VerifiedCall } from '@zk-intent-firewall/mcp-firewall';
import { canonicalAccount } from '@zk-intent-firewall/demo-dashboard/src/shared/demo-config.ts';
import { CALL_ID_META } from '@zk-intent-firewall/demo-dashboard/src/shared/call-id.ts';
import { formatUnits } from '@zk-intent-firewall/demo-dashboard/src/shared/units.ts';
import { z } from 'zod';
import { FAKE_MONEY_NOTICE, FAKE_UNIT } from '../shared/notice.ts';
import { DECIMALS, TOOL_DESCRIPTIONS } from './deployment.ts';
import type { FakeLedger } from './ledger.ts';
import type { PolicyOracle } from './oracle.ts';

export { CALL_ID_META };

export type ToolServerEvent =
  | { readonly callId: string; readonly tool: string; readonly outcome: 'served' }
  | { readonly callId: string; readonly tool: string; readonly outcome: 'rejected'; readonly reason: string; readonly detail?: string }
  | {
      readonly callId: string;
      readonly tool: string;
      readonly outcome: 'executed' | 'insufficient_funds';
      readonly publicInputs: { readonly policyCommitment: string; readonly currentTimestamp: string; readonly actionBinding: string };
      /** Why the published policy does not allow what the verifier accepted. Empty when it does. */
      readonly breakReasons: readonly string[];
      readonly payment?: { readonly tool: string; readonly recipient: string; readonly amount: string; readonly reference: string };
      /** The envelope the call carried, so the caller can try to reuse it. */
      readonly envelope?: IntentEnvelopeWire;
    };

export interface ToolServerContext {
  readonly verifier: IntentVerifier;
  readonly ledger: FakeLedger;
  readonly oracle: PolicyOracle;
  readonly onEvent: (event: ToolServerEvent) => void;
}

const text = (t: string, isError = false): CallToolResult => ({ ...(isError ? { isError: true } : {}), content: [{ type: 'text', text: t }] });

function callIdOf(meta: unknown): string {
  const v = typeof meta === 'object' && meta !== null ? (meta as Record<string, unknown>)[CALL_ID_META] : undefined;
  return typeof v === 'string' && v.length <= 64 ? v : '';
}

function envelopeOf(meta: unknown): IntentEnvelopeWire | undefined {
  const v = typeof meta === 'object' && meta !== null ? (meta as Record<string, unknown>)[INTENT_META_KEY] : undefined;
  return typeof v === 'object' && v !== null ? (v as IntentEnvelopeWire) : undefined;
}

const paymentSchema = { recipient: z.string().max(128), amount: z.union([z.string().max(64), z.number()]) };

/** A fresh MCP server over the shared verifier and ledger, for one connection. */
export function createToolServer(ctx: ToolServerContext): McpServer {
  const server = new McpServer({ name: 'break-it-fake-treasury', version: '0.1.0' });
  const emit = (e: ToolServerEvent) => {
    try {
      ctx.onEvent(e);
    } catch {
      // Logging never changes an outcome.
    }
  };

  server.registerTool('get_balance', { description: TOOL_DESCRIPTIONS['get_balance']!, inputSchema: {} }, async (_args, extra) => {
    emit({ callId: callIdOf(extra._meta), tool: 'get_balance', outcome: 'served' });
    return text(`${FAKE_MONEY_NOTICE}\nTreasury balance: ${formatUnits(ctx.ledger.balance, DECIMALS)} ${FAKE_UNIT}.`);
  });

  for (const tool of ['send_payment', 'treasury_sweep'] as const) {
    server.registerTool(tool, { description: TOOL_DESCRIPTIONS[tool]!, inputSchema: paymentSchema }, async (args, extra) => {
      const callId = callIdOf(extra._meta);
      const guarded = requireProofOfIntent(
        ctx.verifier,
        tool,
        async (a: typeof args, e: typeof extra, v: VerifiedCall) => {
          const publicInputs = {
            policyCommitment: fieldToHex(v.policyCommitment),
            currentTimestamp: v.currentTimestamp.toString(),
            actionBinding: fieldToHex(v.actionBinding),
          };
          const breakReasons = ctx.oracle.violations({ tool, arguments: a, policyCommitment: publicInputs.policyCommitment, at: v.currentTimestamp, paidAmount: v.action.amount });
          if (ctx.oracle.executedTwice(publicInputs.policyCommitment, publicInputs.actionBinding)) breakReasons.push('same_proof_binding_executed_twice');
          const envelope = envelopeOf(e._meta);
          // Execute exactly the call that was bound: the proven amount, to the account the verifier
          // derived the recipient from.
          const paid = ctx.ledger.pay({ tool, recipient: canonicalAccount(a.recipient), amount: v.action.amount });
          if (!paid.ok) {
            emit({ callId, tool, outcome: 'insufficient_funds', publicInputs, breakReasons, ...(envelope ? { envelope } : {}) });
            return text(`${FAKE_MONEY_NOTICE}\nNot paid: the fake treasury cannot cover ${formatUnits(v.action.amount, DECIMALS)} ${FAKE_UNIT}.`, true);
          }
          const payment = { tool, recipient: paid.entry.recipient, amount: paid.entry.amount, reference: paid.entry.reference };
          emit({ callId, tool, outcome: 'executed', publicInputs, breakReasons, payment, ...(envelope ? { envelope } : {}) });
          return text(`${FAKE_MONEY_NOTICE}\nPaid ${formatUnits(paid.entry.amount, DECIMALS)} ${FAKE_UNIT} to ${paid.entry.recipient}. Reference ${paid.entry.reference}.`);
        },
        { onRejected: (_t, reason, detail) => emit({ callId, tool, outcome: 'rejected', reason, ...(detail !== undefined ? { detail } : {}) }) },
      );
      return guarded(args, extra);
    });
  }

  return server;
}
