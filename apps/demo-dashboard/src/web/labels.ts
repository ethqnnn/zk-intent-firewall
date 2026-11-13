/** Human-readable text for reasons, accounts and amounts. */
import { PAYEES, shortAccount, USDC_DECIMALS } from '../shared/demo-config.ts';
import { formatUnits } from '../shared/units.ts';
import type { StoredPolicy } from './storage.ts';

const REASONS: Record<string, string> = {
  // Firewall (prover side)
  recipient_not_allowlisted: 'Recipient is not on the allowlist',
  amount_exceeds_limit: 'Amount is above the per-payment limit',
  amount_zero: 'Amount is zero',
  scope_not_granted: 'The policy does not grant this action',
  scope_out_of_range: 'Unknown scope',
  policy_expired: 'The policy has expired',
  policy_not_active: 'The policy is revoked or not registered',
  circuit_rejected: 'The circuit refused the action',
  proving_failed: 'Proving failed',
  self_verification_failed: 'The proof failed its own check',
  unlisted_tool: 'Tool is not allowed',
  malformed_arguments: 'Malformed arguments',
  rate_limited: 'Too many refusals: locked out',
  internal_error: 'Internal error (failed closed)',
  // Verifier (tool server)
  missing_proof: 'No proof attached',
  malformed_envelope: 'Malformed proof envelope',
  target_not_accepted: 'Proof target not accepted',
  unknown_tool: 'Unknown tool',
  commitment_unknown: 'Policy is not registered',
  commitment_revoked: 'Policy was revoked',
  timestamp_stale: 'Proof timestamp is stale',
  timestamp_in_future: 'Proof timestamp is in the future',
  replayed: 'Proof was already used',
  invalid_proof: 'Proof does not verify',
};

export const reasonText = (r: string | undefined): string => (r ? (REASONS[r] ?? r) : '');

const KNOWN: Record<string, string> = Object.fromEntries(Object.values(PAYEES).map((p) => [p.account, p.label]));

export function accountLabel(account: string | undefined, policies: readonly StoredPolicy[] = []): string {
  if (!account) return 'unknown';
  const canonical = account.toLowerCase().startsWith('0x') ? `eip155:1:${account.toLowerCase()}` : account.toLowerCase();
  for (const p of policies) for (const payee of p.definition.payees) if (payee.account === canonical) return payee.label;
  return KNOWN[canonical] ?? 'Unknown wallet';
}

export const usdc = (base: string | bigint | undefined): string => (base === undefined ? '' : `${formatUnits(base, USDC_DECIMALS)} USDC`);
export const short = shortAccount;
export const shortHex = (h: string | undefined): string => (h && h.length > 14 ? `${h.slice(0, 8)}…${h.slice(-6)}` : (h ?? ''));
export const time = (unix: string | undefined): string => (unix ? new Date(Number(unix) * 1000).toLocaleTimeString() : '');
