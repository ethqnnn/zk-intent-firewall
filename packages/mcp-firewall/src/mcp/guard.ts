/**
 * The tool server's side: a tool handler runs only after IntentVerifier accepts the call's proof.
 *
 *   server.registerTool('send_payment', config,
 *     requireProofOfIntent(verifier, 'send_payment', async (args, extra, verified) => { ... }));
 */
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import type { ToolArguments } from '../tools.js';
import type { IntentVerifier, RejectionReason, VerificationResult } from '../verifier/intent-verifier.js';

export type VerifiedCall = Extract<VerificationResult, { ok: true }>;

export interface GuardOptions {
  /** Called on every rejection, for the server's audit log. */
  readonly onRejected?: (toolName: string, reason: RejectionReason, detail?: string) => void;
}

export function rejectedResult(): CallToolResult {
  return { isError: true, content: [{ type: 'text', text: 'Rejected: this call carries no valid proof of intent.' }] };
}

/**
 * Wraps a tool handler. `toolName` must be the name the handler is registered under and must be
 * in the verifier's catalog. The handler receives the verified action; it must execute exactly
 * the call described by `args`, which is what the proof is bound to.
 */
export function requireProofOfIntent<A extends ToolArguments, E extends { readonly _meta?: unknown }>(
  verifier: IntentVerifier,
  toolName: string,
  handler: (args: A, extra: E, verified: VerifiedCall) => CallToolResult | Promise<CallToolResult>,
  options: GuardOptions = {},
): (args: A, extra: E) => Promise<CallToolResult> {
  if (!verifier.catalog.has(toolName)) throw new Error(`tool ${toolName} is not in the verifier's catalog`);
  return async (args, extra) => {
    const result = await verifier.verify(toolName, args, extra._meta);
    if (!result.ok) {
      try {
        options.onRejected?.(toolName, result.reason, result.detail);
      } catch {
        // Logging must not change the outcome.
      }
      return rejectedResult();
    }
    return handler(args, extra, result);
  };
}
