/**
 * The demo deployment: one treasury tool server, its tools and scopes, and the parties named in
 * the scripted scenario. Shared by the browser and the Node processes; no secrets live here.
 */

/** Identity of the tool server, hashed into every tool_id (spec 10.4). */
export const TREASURY_SERVER_ID = 'https://treasury.acme.example/mcp';

/** USDC on Ethereum mainnet (CAIP-19). The payment tool is fixed to this asset (spec L5). */
export const USDC_ASSET_ID = 'eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
export const USDC_DECIMALS = 6;

/** The shared scope registry (spec L7): scope name to bit position. */
export const SCOPES = {
  'inbox.read': 0,
  'payments.send': 3,
  'vendors.write': 5,
  'treasury.admin': 9,
} as const;
export type ScopeName = keyof typeof SCOPES;

export const SCOPE_DESCRIPTIONS: Readonly<Record<ScopeName, string>> = {
  'inbox.read': 'Read the accounts-payable inbox (read-only tools never need a proof)',
  'payments.send': 'Send USDC payments to allowlisted payees',
  'vendors.write': 'Change vendor master data, such as payout addresses',
  'treasury.admin': 'Move treasury funds between internal accounts',
};

/** Tools that move value and need a proof of intent. */
export const PROTECTED_TOOLS = {
  send_payment: { scope: 'payments.send' as ScopeName, description: 'Send a USDC payment on Ethereum. Arguments: recipient (CAIP-10 or 0x address), amount (base units, 6 decimals).' },
} as const;

/** Read-only tools the firewall passes through without a proof. */
export const PASSTHROUGH_TOOLS = ['list_inbox', 'read_message'] as const;

export interface Payee {
  readonly label: string;
  /** CAIP-10 account, lowercase. */
  readonly account: string;
}

export const PAYEES = {
  northwind: { label: 'Northwind Logistics', account: 'eip155:1:0x95ba5d066b3932df37ec05ff73eb1e5c95b2c3d5' },
  contoso: { label: 'Contoso Cloud', account: 'eip155:1:0x6231e88007c7cd916923312bcea5df2a4410eb67' },
  fabrikam: { label: 'Fabrikam Office Supply', account: 'eip155:1:0x033bcf9ae9d036805a911181010f90566022735e' },
  litware: { label: 'Litware Payroll Services', account: 'eip155:1:0x0526420963472beaad0380f318b603e87f1defaf' },
} as const satisfies Record<string, Payee>;

/**
 * The attacker's wallet. It shares its first and last characters with Northwind's address, the
 * "address poisoning" pattern that defeats a human glancing at both ends of an address.
 */
export const ATTACKER_ACCOUNT = 'eip155:1:0x95ba5d403baf29683895e916b05b90e04fb2c3d5';

/** The policy the dashboard offers as a starting point. */
export const DEMO_POLICY_PRESET = {
  name: 'AP agent: vendor payments',
  maxAmountUsdc: '5000',
  payees: [PAYEES.northwind, PAYEES.contoso, PAYEES.fabrikam, PAYEES.litware],
  scopes: ['payments.send'] as ScopeName[],
  validForDays: 30,
} as const;

export class AccountFormatError extends Error {
  override readonly name = 'AccountFormatError';
}

const CAIP10_EVM = /^eip155:([1-9][0-9]{0,15}):0x([0-9a-fA-F]{40})$/;
const BARE_EVM = /^0x([0-9a-fA-F]{40})$/;

/**
 * The canonical form of an EVM account: `eip155:<chain>:0x<40 lowercase hex>`. A bare 0x address
 * means Ethereum mainnet. The recipient identifier hashes this string (spec 10.4), so every party
 * must canonicalise the same way: the same address in another letter case is the same payee.
 */
export function canonicalAccount(input: unknown): string {
  if (typeof input !== 'string') throw new AccountFormatError('account must be a string');
  const s = input.trim();
  const caip = CAIP10_EVM.exec(s);
  if (caip) return `eip155:${caip[1]}:0x${caip[2]!.toLowerCase()}`;
  const bare = BARE_EVM.exec(s);
  if (bare) return `eip155:1:0x${bare[1]!.toLowerCase()}`;
  throw new AccountFormatError('account must be eip155:<chain>:0x<40 hex digits> or a 0x address');
}

/** "0x95ba…c3d5" for display. */
export function shortAccount(account: string): string {
  const addr = account.slice(account.lastIndexOf(':') + 1);
  return addr.length > 12 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;
}
