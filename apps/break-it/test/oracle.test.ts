import { describe, expect, it } from 'vitest';
import { PolicyOracle } from '../src/engine/oracle.ts';

const C = `0x${'1'.repeat(64)}`;
const OK = 'eip155:1:0x95ba5d066b3932df37ec05ff73eb1e5c95b2c3d5';
const LOOKALIKE = 'eip155:1:0x95ba5d403baf29683895e916b05b90e04fb2c3d5';

const oracle = () => new PolicyOracle({ policyCommitment: C, maxAmount: 500_000_000n, allowlist: [OK], grantedTools: ['send_payment'], expiry: 2_000_000_000n });
const base = { tool: 'send_payment', policyCommitment: C, at: 1_900_000_000n };

describe('break detector', () => {
  it('finds nothing wrong with an in-policy payment, in any accepted spelling', () => {
    const o = oracle();
    expect(o.violations({ ...base, arguments: { recipient: OK, amount: '500000000' }, paidAmount: 500_000_000n })).toEqual([]);
    expect(o.violations({ ...base, arguments: { recipient: '0x95BA5D066B3932DF37EC05FF73EB1E5C95B2C3D5', amount: 1 } })).toEqual([]);
  });

  it.each([
    ['a lookalike recipient', { arguments: { recipient: LOOKALIKE, amount: '1' } }, 'recipient_not_allowlisted'],
    ['the right address on another chain', { arguments: { recipient: OK.replace('eip155:1:', 'eip155:5:'), amount: '1' } }, 'recipient_not_allowlisted'],
    ['an amount over the limit', { arguments: { recipient: OK, amount: '500000001' } }, 'amount_exceeds_limit'],
    ['a zero amount', { arguments: { recipient: OK, amount: '0' } }, 'amount_zero'],
    ['a paid amount that differs from the request', { arguments: { recipient: OK, amount: '10' }, paidAmount: 11n }, 'paid_amount_differs_from_requested'],
    ['an ungranted tool', { tool: 'treasury_sweep', arguments: { recipient: OK, amount: '1' } }, 'tool_scope_not_granted'],
    ['an extra argument', { arguments: { recipient: OK, amount: '1', memo: 'x' } }, 'arguments_not_bound_by_the_proof'],
    ['another commitment', { policyCommitment: `0x${'2'.repeat(64)}`, arguments: { recipient: OK, amount: '1' } }, 'not_the_published_policy_commitment'],
    ['a timestamp at expiry', { at: 2_000_000_000n, arguments: { recipient: OK, amount: '1' } }, 'policy_expired'],
    ['an unparseable amount', { arguments: { recipient: OK, amount: '1e3' } }, 'amount_unparseable'],
    ['an unparseable recipient', { arguments: { recipient: 'alice', amount: '1' } }, 'recipient_unparseable'],
  ])('flags %s', (_name, change, reason) => {
    expect(oracle().violations({ ...base, ...change } as never)).toContain(reason);
  });

  it('flags the second execution of one binding', () => {
    const o = oracle();
    expect(o.executedTwice(C, '0xab')).toBe(false);
    expect(o.executedTwice(C, '0xac')).toBe(false);
    expect(o.executedTwice(C, '0xab')).toBe(true);
  });
});
