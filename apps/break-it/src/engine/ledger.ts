/**
 * The fake ledger the break-it tool server pays from. It is an in-memory balance sheet and nothing
 * else: no payment rail, no chain, no external account. A payment only ever changes numbers in this
 * object.
 *
 * Only the tool server's handlers call `pay`, and they run only after IntentVerifier accepted the
 * call's proof. A call that is blocked or rejected never reaches the ledger, so it cannot change a
 * balance.
 */
import { randomUUID } from 'node:crypto';
import { unixNow } from '@zk-intent-firewall/mcp-firewall';

export interface LedgerOptions {
  /** The treasury's balance at start, in base units. */
  readonly openingBalance: bigint;
  /**
   * After a payment leaves the treasury below this, it is topped back up to the opening balance,
   * and the top-up is recorded. Default 0n: never. (The policy has no cumulative budget, spec L1,
   * so draining the treasury with in-policy payments is not a break; topping up keeps the
   * environment usable for everyone.)
   */
  readonly topUpBelow?: bigint;
  /** Entries kept in `history`. Default 200. */
  readonly historyLimit?: number;
  readonly clock?: () => bigint;
}

export type LedgerEntry =
  | {
      readonly kind: 'payment';
      readonly reference: string;
      readonly tool: string;
      readonly recipient: string;
      /** Base units, decimal. */
      readonly amount: string;
      /** Treasury balance after the payment, decimal. */
      readonly balanceAfter: string;
      /** Unix seconds, decimal. */
      readonly at: string;
    }
  | { readonly kind: 'top_up'; readonly reference: string; readonly amount: string; readonly balanceAfter: string; readonly at: string };

export type PaymentResult =
  | { readonly ok: true; readonly entry: Extract<LedgerEntry, { kind: 'payment' }>; readonly topUp?: Extract<LedgerEntry, { kind: 'top_up' }> }
  | { readonly ok: false; readonly reason: 'insufficient_funds' | 'invalid_amount' };

export interface LedgerSnapshot {
  readonly treasury: { readonly openingBalance: string; readonly balance: string };
  readonly totals: { readonly payments: number; readonly paidOut: string; readonly topUps: number; readonly toppedUp: string };
  /** Amount received per recipient account, decimal base units. */
  readonly received: Readonly<Record<string, string>>;
  /** Most recent first. */
  readonly history: readonly LedgerEntry[];
}

export class FakeLedger {
  readonly openingBalance: bigint;
  readonly #topUpBelow: bigint;
  readonly #historyLimit: number;
  readonly #clock: () => bigint;
  #balance: bigint;
  #payments = 0;
  #paidOut = 0n;
  #topUps = 0;
  #toppedUp = 0n;
  readonly #received = new Map<string, bigint>();
  readonly #history: LedgerEntry[] = [];

  constructor(o: LedgerOptions) {
    if (o.openingBalance <= 0n) throw new Error('the opening balance must be positive');
    this.openingBalance = o.openingBalance;
    this.#balance = o.openingBalance;
    this.#topUpBelow = o.topUpBelow ?? 0n;
    if (this.#topUpBelow < 0n || this.#topUpBelow > o.openingBalance) throw new Error('topUpBelow must be between 0 and the opening balance');
    this.#historyLimit = o.historyLimit ?? 200;
    this.#clock = o.clock ?? unixNow;
  }

  get balance(): bigint {
    return this.#balance;
  }

  /** Moves `amount` from the treasury to `recipient`. Never goes below zero. */
  pay(p: { readonly tool: string; readonly recipient: string; readonly amount: bigint }): PaymentResult {
    if (typeof p.amount !== 'bigint' || p.amount <= 0n) return { ok: false, reason: 'invalid_amount' };
    if (p.amount > this.#balance) return { ok: false, reason: 'insufficient_funds' };
    this.#balance -= p.amount;
    this.#payments += 1;
    this.#paidOut += p.amount;
    this.#received.set(p.recipient, (this.#received.get(p.recipient) ?? 0n) + p.amount);
    const entry = {
      kind: 'payment' as const,
      reference: `fake-tx-${randomUUID().slice(0, 8)}`,
      tool: p.tool,
      recipient: p.recipient,
      amount: p.amount.toString(),
      balanceAfter: this.#balance.toString(),
      at: this.#clock().toString(),
    };
    this.#record(entry);
    const topUp = this.#balance < this.#topUpBelow ? this.#topUp() : undefined;
    return topUp ? { ok: true, entry, topUp } : { ok: true, entry };
  }

  #topUp(): Extract<LedgerEntry, { kind: 'top_up' }> {
    const amount = this.openingBalance - this.#balance;
    this.#balance = this.openingBalance;
    this.#topUps += 1;
    this.#toppedUp += amount;
    const entry = {
      kind: 'top_up' as const,
      reference: `fake-topup-${randomUUID().slice(0, 8)}`,
      amount: amount.toString(),
      balanceAfter: this.#balance.toString(),
      at: this.#clock().toString(),
    };
    this.#record(entry);
    return entry;
  }

  #record(entry: LedgerEntry): void {
    this.#history.push(entry);
    if (this.#history.length > this.#historyLimit) this.#history.splice(0, this.#history.length - this.#historyLimit);
  }

  snapshot(): LedgerSnapshot {
    return {
      treasury: { openingBalance: this.openingBalance.toString(), balance: this.#balance.toString() },
      totals: { payments: this.#payments, paidOut: this.#paidOut.toString(), topUps: this.#topUps, toppedUp: this.#toppedUp.toString() },
      received: Object.fromEntries([...this.#received].map(([k, v]) => [k, v.toString()])),
      history: [...this.#history].reverse(),
    };
  }
}
