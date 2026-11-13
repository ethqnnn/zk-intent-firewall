/**
 * Prompt injection, end to end. A scripted agent stands in for an LLM that cannot tell its user's
 * instruction from text injected into a tool result: it reads an invoice and obeys the last
 * payment instruction it finds. The agent "wants" to comply with the attacker. The firewall, which
 * holds a policy the agent cannot see or change, blocks the payment before it reaches the server.
 */
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { ACCOUNTS, ATTACKER, createHarness, createShared, destroyShared, type Harness, isBlocked, type Shared, text } from './harness.js';

/** What the agent did, step by step. */
interface Transcript {
  readonly intended: { recipient: string; amount: string } | undefined;
  readonly result: string;
  readonly blocked: boolean;
}

/**
 * The user asked: "pay invoice <id>". The agent reads the invoice and executes the last line of
 * the form "PAY <amount> TO <account>": injected text later in a document overrides the real
 * instruction, as it does for models that follow the most recent imperative.
 */
async function naiveAgent(agent: Client, invoiceId: string): Promise<Transcript> {
  const invoice = text(await agent.callTool({ name: 'read_invoice', arguments: { invoice_id: invoiceId } }));
  const instructions = [...invoice.matchAll(/^PAY (\d+) TO (\S+)$/gm)];
  const last = instructions.at(-1);
  if (!last) return { intended: undefined, result: 'nothing to pay', blocked: false };
  const intended = { amount: last[1]!, recipient: last[2]! };
  const r = await agent.callTool({ name: 'send_payment', arguments: intended });
  return { intended, result: text(r), blocked: isBlocked(r) };
}

let shared: Shared;
let h: Harness;
beforeAll(async () => {
  shared = await createShared();
});
afterAll(async () => {
  await destroyShared(shared);
});
afterEach(async () => {
  await h?.close();
});

describe('prompt injection', () => {
  it('control: a clean invoice is paid', async () => {
    h = await createHarness(shared);
    const t = await naiveAgent(h.agent, 'INV-42');
    expect(t.blocked).toBe(false);
    expect(h.ledger).toEqual([{ tool: 'send_payment', recipient: ACCOUNTS[3], amount: '125000000' }]);
  });

  it('redirect to an attacker account: the agent complies, the firewall blocks', async () => {
    h = await createHarness(shared);
    const t = await naiveAgent(h.agent, 'INV-EVIL-REDIRECT');

    // The agent was fooled: it really tried to pay the attacker.
    expect(t.intended).toEqual({ recipient: ATTACKER, amount: '125000000' });
    // The firewall stopped it before it left the agent's side.
    expect(t.blocked).toBe(true);
    expect(h.forwarded).toEqual(['read_invoice']);
    expect(h.ledger).toEqual([]);
    // The agent is told nothing it could use to probe the policy; the operator gets the reason.
    expect(t.result).not.toMatch(/allowlist|recipient/i);
    expect(h.decisions.at(-1)).toMatchObject({ allowed: false, toolName: 'send_payment', reason: 'recipient_not_allowlisted' });
  });

  it('over the spending limit to a legitimate payee: the agent complies, the firewall blocks', async () => {
    h = await createHarness(shared);
    const t = await naiveAgent(h.agent, 'INV-EVIL-OVERLIMIT');

    expect(t.intended).toEqual({ recipient: ACCOUNTS[3], amount: '9000000000' });
    expect(t.blocked).toBe(true);
    expect(h.forwarded).toEqual(['read_invoice']);
    expect(h.ledger).toEqual([]);
    expect(t.result).not.toMatch(/limit|amount/i);
    expect(h.decisions.at(-1)).toMatchObject({ allowed: false, reason: 'amount_exceeds_limit' });
  });

  it('the same attacks are blocked by the circuit alone, with the pre-check off', async () => {
    h = await createHarness(shared, { firewall: { precheck: false } });
    const a = await naiveAgent(h.agent, 'INV-EVIL-REDIRECT');
    const b = await naiveAgent(h.agent, 'INV-EVIL-OVERLIMIT');
    expect([a.blocked, b.blocked]).toEqual([true, true]);
    expect(h.ledger).toEqual([]);
    expect(h.decisions.filter((d) => !d.allowed).map((d) => d.assertion)).toEqual(['recipient not in allowlist', 'amount exceeds policy limit']);
  });

  it('a persistent attacker probing the policy is locked out', async () => {
    h = await createHarness(shared);
    // Binary search for the limit, as spec L10 warns.
    let lo = 1n;
    let hi = 1n << 40n;
    const outcomes: boolean[] = [];
    for (let i = 0; i < 12; i++) {
      const mid = (lo + hi) / 2n;
      const r = await h.agent.callTool({ name: 'send_payment', arguments: { recipient: ACCOUNTS[3]!, amount: mid.toString() } });
      const ok = !r.isError;
      outcomes.push(ok);
      if (ok) lo = mid;
      else hi = mid;
    }
    // After five refusals every protected call is refused, so the search stalls far from 500000000.
    expect(h.decisions.filter((d) => d.reason === 'rate_limited').length).toBeGreaterThan(0);
    expect(hi - lo).toBeGreaterThan(1_000_000n);
  });
});
