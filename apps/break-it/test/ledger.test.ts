import { describe, expect, it } from 'vitest';
import { FakeLedger } from '../src/engine/ledger.ts';
import { OPENING_BALANCE } from '../src/engine/deployment.ts';

const USDC = 1_000_000n;
const A = 'eip155:1:0x95ba5d066b3932df37ec05ff73eb1e5c95b2c3d5';
const B = 'eip155:1:0x6231e88007c7cd916923312bcea5df2a4410eb67';

describe('fake ledger', () => {
  it('the deployment opens at exactly 10,000 fake USDC', () => {
    expect(OPENING_BALANCE).toBe(10_000n * USDC);
    const l = new FakeLedger({ openingBalance: OPENING_BALANCE });
    expect(l.balance).toBe(10_000n * USDC);
    expect(l.snapshot()).toMatchObject({
      treasury: { openingBalance: '10000000000', balance: '10000000000' },
      totals: { payments: 0, paidOut: '0', topUps: 0, toppedUp: '0' },
      received: {},
      history: [],
    });
  });

  it('a payment decrements the treasury by exactly its amount and credits the recipient', () => {
    const l = new FakeLedger({ openingBalance: 10_000n * USDC, clock: () => 1_800_000_000n });
    const r = l.pay({ tool: 'send_payment', recipient: A, amount: 1_250_500_000n });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(l.balance).toBe(10_000n * USDC - 1_250_500_000n);
    expect(r.entry).toMatchObject({ kind: 'payment', tool: 'send_payment', recipient: A, amount: '1250500000', balanceAfter: '8749500000', at: '1800000000' });
    expect(r.entry.reference).toMatch(/^fake-tx-[0-9a-f]{8}$/);
    l.pay({ tool: 'send_payment', recipient: A, amount: 1n });
    l.pay({ tool: 'send_payment', recipient: B, amount: 2n });
    const s = l.snapshot();
    expect(s.received).toEqual({ [A]: '1250500001', [B]: '2' });
    expect(s.totals).toMatchObject({ payments: 3, paidOut: '1250500003' });
    expect(s.history.map((e) => e.amount)).toEqual(['2', '1', '1250500000']);
  });

  it('refuses a payment above the balance, and zero, negative or non-bigint amounts, without touching anything', () => {
    const l = new FakeLedger({ openingBalance: 100n });
    const before = JSON.stringify(l.snapshot());
    expect(l.pay({ tool: 't', recipient: A, amount: 101n })).toEqual({ ok: false, reason: 'insufficient_funds' });
    expect(l.pay({ tool: 't', recipient: A, amount: 0n })).toEqual({ ok: false, reason: 'invalid_amount' });
    expect(l.pay({ tool: 't', recipient: A, amount: -5n })).toEqual({ ok: false, reason: 'invalid_amount' });
    expect(l.pay({ tool: 't', recipient: A, amount: 5 as unknown as bigint })).toEqual({ ok: false, reason: 'invalid_amount' });
    expect(JSON.stringify(l.snapshot())).toBe(before);
    expect(l.pay({ tool: 't', recipient: A, amount: 100n }).ok).toBe(true);
    expect(l.balance).toBe(0n);
  });

  it('without top-up, the treasury can be drained to zero and no further', () => {
    const l = new FakeLedger({ openingBalance: 10n });
    for (let i = 0; i < 10; i++) expect(l.pay({ tool: 't', recipient: A, amount: 1n }).ok).toBe(true);
    expect(l.pay({ tool: 't', recipient: A, amount: 1n })).toEqual({ ok: false, reason: 'insufficient_funds' });
    expect(l.balance).toBe(0n);
  });

  it('tops up to the opening balance when a payment leaves it below the threshold, and records the top-up', () => {
    const l = new FakeLedger({ openingBalance: 1000n, topUpBelow: 300n });
    expect(l.pay({ tool: 't', recipient: A, amount: 600n })).toMatchObject({ ok: true });
    expect(l.balance).toBe(400n);
    const r = l.pay({ tool: 't', recipient: A, amount: 200n });
    expect(r).toMatchObject({ ok: true, entry: { balanceAfter: '200' }, topUp: { kind: 'top_up', amount: '800', balanceAfter: '1000' } });
    expect(l.balance).toBe(1000n);
    expect(l.snapshot().totals).toMatchObject({ payments: 2, paidOut: '800', topUps: 1, toppedUp: '800' });
  });

  it('keeps a bounded history, most recent first', () => {
    const l = new FakeLedger({ openingBalance: 1000n, historyLimit: 3 });
    for (let i = 1; i <= 5; i++) l.pay({ tool: 't', recipient: A, amount: BigInt(i) });
    expect(l.snapshot().history.map((e) => e.amount)).toEqual(['5', '4', '3']);
    expect(l.snapshot().totals.payments).toBe(5);
  });

  it('rejects nonsensical configurations', () => {
    expect(() => new FakeLedger({ openingBalance: 0n })).toThrow();
    expect(() => new FakeLedger({ openingBalance: 10n, topUpBelow: 11n })).toThrow();
  });
});
