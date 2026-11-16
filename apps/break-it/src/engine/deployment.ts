/**
 * What the break-it instance runs: its tools, its scopes, and the policy in force. The policy's
 * limit, allowlist, scopes and expiry are published on the page; only the salt stays secret, as it
 * would in a real deployment (it is what keeps the commitment hiding, spec section 2).
 *
 * The tool definitions are the demo dashboard's, reused as they are: `sendPayment` binds amount and
 * recipient and refuses any other argument (apps/demo-dashboard/src/server/tools.ts).
 */
import { type ToolActionSpec, ToolCatalog } from '@zk-intent-firewall/mcp-firewall';
import { sendPayment } from '@zk-intent-firewall/demo-dashboard/src/server/tools.ts';
import { ATTACKER_ACCOUNT, PAYEES, type Payee, SCOPES, type ScopeName, USDC_ASSET_ID, USDC_DECIMALS } from '@zk-intent-firewall/demo-dashboard/src/shared/demo-config.ts';

export { USDC_ASSET_ID as ASSET_ID, USDC_DECIMALS as DECIMALS, SCOPES };

/**
 * A second protected tool that moves funds, under a scope the policy does not grant. It uses the
 * same argument mapping as send_payment, so the only difference the proof sees is tool and scope.
 */
export const treasurySweep: ToolActionSpec = { ...sendPayment, name: 'treasury_sweep', scope: 'treasury.admin' satisfies ScopeName };

export const PROTECTED_TOOLS: readonly ToolActionSpec[] = [sendPayment, treasurySweep];

export const TOOL_DESCRIPTIONS: Readonly<Record<string, string>> = {
  send_payment: 'Pay fake USDC from the test treasury. Arguments: recipient (CAIP-10 or 0x address), amount (base units, 6 decimals). Needs scope payments.send.',
  treasury_sweep: 'Move fake USDC out of the test treasury. Same arguments as send_payment. Needs scope treasury.admin, which the policy does not grant.',
  get_balance: 'Read the fake treasury balance. Read-only: the firewall passes it through without a proof.',
};

/** Read-only tools the firewall forwards without a proof. */
export const PASSTHROUGH_TOOLS = ['get_balance'] as const;

export function breakItCatalog(serverId: string): ToolCatalog {
  return new ToolCatalog({ serverId, tools: PROTECTED_TOOLS, scopes: SCOPES });
}

export interface BreakItPolicy {
  /** Base units. */
  readonly maxAmount: bigint;
  readonly payees: readonly Payee[];
  readonly scopes: readonly ScopeName[];
  /** Seconds the policy is valid for, from boot. */
  readonly validForSeconds: bigint;
}

/** The policy in force. 500 fake USDC per payment, three payees, payments only, 90 days. */
export const BREAK_IT_POLICY: BreakItPolicy = {
  maxAmount: 500n * 10n ** BigInt(USDC_DECIMALS),
  payees: [PAYEES.northwind, PAYEES.contoso, PAYEES.fabrikam],
  scopes: ['payments.send'],
  validForSeconds: 90n * 24n * 3600n,
};

/** The fake treasury's opening balance: 10,000 fake USDC. */
export const OPENING_BALANCE = 10_000n * 10n ** BigInt(USDC_DECIMALS);

/** Addresses offered as starting points on the page. None is allowlisted. */
export const NOT_ALLOWLISTED = {
  /** Shares its first and last characters with Northwind's address (address poisoning). */
  lookalike: { label: 'Lookalike of Northwind (address poisoning)', account: ATTACKER_ACCOUNT },
  /** A real-looking payee that the policy leaves out. */
  litware: PAYEES.litware,
} as const;
