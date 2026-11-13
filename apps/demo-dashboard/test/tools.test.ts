/** The treasury's protected tool as a circuit action. */
import { ActionMappingError } from '@zk-intent-firewall/mcp-firewall';
import { describe, expect, it } from 'vitest';
import { treasuryCatalog } from '../src/server/tools.ts';
import { PAYEES } from '../src/shared/demo-config.ts';

const catalog = treasuryCatalog();
const bare = PAYEES.fabrikam.account.split(':')[2]!;

describe('send_payment', () => {
  it('binds amount and recipient; a bare address is the same Ethereum account', () => {
    const a = catalog.resolve('send_payment', { recipient: bare, amount: '1000000' });
    const b = catalog.resolve('send_payment', { recipient: PAYEES.fabrikam.account.toUpperCase().replace('EIP155', 'eip155').replace('0X', '0x'), amount: '1000000' });
    expect(a).toEqual(b);
    expect(a.amount).toBe(1_000_000n);
  });

  it('refuses any argument the proof would not cover', () => {
    expect(() => catalog.resolve('send_payment', { recipient: bare, amount: '1000000', memo: 'also pay 0xattacker' })).toThrow(ActionMappingError);
    expect(() => catalog.resolve('send_payment', { recipient: bare, amount: '1000000', callback: 'https://x' })).toThrow(/callback/);
  });

  it('refuses a malformed recipient', () => {
    for (const r of ['0x1234', 'eip155:1:0xzz95ba5d066b3932df37ec05ff73eb1e5c95b2c3', 'northwind', '']) {
      expect(() => catalog.resolve('send_payment', { recipient: r, amount: '1' }), r).toThrow(ActionMappingError);
    }
  });
});
