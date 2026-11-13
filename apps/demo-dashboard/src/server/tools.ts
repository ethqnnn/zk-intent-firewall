/**
 * The treasury's protected tools as circuit actions. The firewall and the tool server each build a
 * ToolCatalog from these same definitions; the tool server's copy, with its own server identity, is
 * the one that counts (spec 10.3 step 3).
 */
import { ActionMappingError, amountArg, type ToolActionSpec, type ToolArguments, ToolCatalog } from '@zk-intent-firewall/mcp-firewall';
import { AccountFormatError, canonicalAccount, SCOPES, TREASURY_SERVER_ID, USDC_ASSET_ID } from '../shared/demo-config.ts';

const SEND_PAYMENT_ARGS = new Set(['recipient', 'amount']);

/** The canonical CAIP-10 account in `args.recipient`. */
export function recipientArg(args: ToolArguments): string {
  try {
    return canonicalAccount(args['recipient']);
  } catch (e) {
    throw new ActionMappingError(e instanceof AccountFormatError ? `argument recipient: ${e.message}` : 'argument recipient is not an account');
  }
}

/**
 * `send_payment(recipient, amount)`: moves `amount` base units of USDC on Ethereum to `recipient`.
 * Any other argument is refused: the proof binds tool, scope, amount and recipient only, so an
 * extra argument would reach the tool without being covered by the proof.
 */
export const sendPayment: ToolActionSpec = {
  name: 'send_payment',
  scope: 'payments.send',
  effect: (args) => {
    for (const k of Object.keys(args)) {
      if (!SEND_PAYMENT_ARGS.has(k)) throw new ActionMappingError(`argument ${k} is not accepted by send_payment`);
    }
    return { amount: amountArg(args, 'amount'), recipient: { assetId: USDC_ASSET_ID, accountId: recipientArg(args) } };
  },
};

export const PROTECTED_TOOL_SPECS: readonly ToolActionSpec[] = [sendPayment];

export function treasuryCatalog(serverId: string = TREASURY_SERVER_ID): ToolCatalog {
  return new ToolCatalog({ serverId, tools: PROTECTED_TOOL_SPECS, scopes: SCOPES });
}
