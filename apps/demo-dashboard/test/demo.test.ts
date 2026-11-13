/**
 * The live demo, end to end with real processes: the scripted agent in its sandbox, the firewall
 * proving in this process, the treasury verifying in its own. Nothing is mocked: the outcomes come
 * from the policy and the proofs, as the anti-stub test shows by changing the policy and watching
 * the same attacks go through.
 */
import { encodeEnvelope, getHasher, INTENT_META_KEY, type IntentEnvelope, IntentFirewall, LocalWasmProver, PolicyOpening } from '@zk-intent-firewall/mcp-firewall';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { presetPolicy, setUpDemo } from '../src/demo/flow.ts';
import type { SoftAuthenticator } from '../src/demo/soft-authenticator.ts';
import type { Host } from '../src/server/host/host.ts';
import { treasuryCatalog } from '../src/server/tools.ts';
import { ATTACKER_ACCOUNT, PAYEES } from '../src/shared/demo-config.ts';
import { forwardedCalls, payments, startHost, type Wire } from './helpers.ts';

const addr = (account: string) => account.split(':')[2]!;

describe('the scripted attack against the preset policy', () => {
  let host: Host;
  let auth: SoftAuthenticator;
  let wire: Wire;
  let run: Awaited<ReturnType<Host['runDemo']>>;
  let opening: unknown;

  beforeAll(async () => {
    ({ host, auth, wire } = await startHost());
    opening = (await setUpDemo(host, auth)).policy.opening;
    run = await host.runDemo();
  });
  afterAll(async () => host?.stop());

  it('the agent was really fooled: it asked for the attacker’s wallet and the inflated amount', () => {
    expect(run.exitCode).toBe(0);
    const ps = payments(run);
    expect(ps.map((p) => [p.recipient.toLowerCase(), p.amount])).toEqual([
      // Base units (6 decimals), as the tool takes them.
      [addr(PAYEES.northwind.account), '1250000000'],
      [addr(ATTACKER_ACCOUNT), '2980000000'],
      [addr(PAYEES.contoso.account), '48750000000'],
      [addr(PAYEES.fabrikam.account), '412600000'],
    ]);
    expect(run.steps.filter((s) => s.kind === 'thought' && s.flagged)).toHaveLength(2);
  });

  it('legitimate payments are proven by the firewall and verified by the treasury', () => {
    for (const i of [0, 3]) {
      const p = payments(run)[i]!;
      expect(p.firewall).toMatchObject({ allowed: true });
      // Real proving takes real time; a stub would not.
      expect(p.firewall!.elapsedMs).toBeGreaterThan(50);
      expect(p.verifier).toMatchObject({ outcome: 'executed', target: 'noir-recursive', proofBytes: 14_656 });
      expect(p.verifier!.payment).toEqual({ recipient: expect.stringContaining(p.recipient.toLowerCase()), amount: expect.any(String) });
    }
  });

  it('the redirect is blocked for the recipient, the inflation for the amount, and neither is forwarded', () => {
    const [, redirect, inflate] = payments(run);
    expect(redirect!.firewall).toMatchObject({ allowed: false, reason: 'recipient_not_allowlisted' });
    expect(inflate!.firewall).toMatchObject({ allowed: false, reason: 'amount_exceeds_limit' });
    for (const p of [redirect!, inflate!]) {
      expect(p.verifier).toBeUndefined();
      expect(forwardedCalls(wire, p.callId)).toHaveLength(0);
    }
  });

  it('the agent learns nothing about the policy from a refusal', () => {
    const results = run.steps.filter((s) => s.kind === 'tool_result' && s.isError);
    expect(results).toHaveLength(2);
    for (const r of results) {
      expect(r.kind === 'tool_result' && r.text).toMatch(/^Blocked by the intent firewall: this action is not authorised\. Decision [0-9a-f-]{36}\.?$/);
    }
  });

  it('only the two legitimate payments reached the ledger', async () => {
    const { ledger } = await host.log();
    expect(ledger.map((l) => [l.recipient, l.amount])).toEqual([
      [PAYEES.northwind.account, '1250000000'],
      [PAYEES.fabrikam.account, '412600000'],
    ]);
  });

  describe('calling the treasury directly, around the firewall', () => {
    let ledgerSize: number;
    let firewall: IntentFirewall;
    let prover: LocalWasmProver;
    // A fresh, valid proof for a payment the treasury has never seen, made by a second firewall
    // holding the same opening.
    const payment = { recipient: addr(PAYEES.fabrikam.account), amount: '100000000' };
    let envelope: IntentEnvelope;

    beforeAll(async () => {
      ledgerSize = (await host.log()).ledger.length;
      prover = await LocalWasmProver.create({ threads: 4 });
      firewall = await IntentFirewall.create({ policy: PolicyOpening.fromJSON(await getHasher(), opening as never), catalog: treasuryCatalog(), prover, refusalLimit: false });
      const a = await firewall.authorize('send_payment', payment);
      if (!a.allowed || !a.protected) throw new Error('the second firewall refused a legitimate payment');
      envelope = a.envelope;
    });
    afterAll(async () => {
      await firewall?.destroy();
      await prover?.destroy();
    });

    const send = async (args: Record<string, unknown>, env?: unknown) => {
      const r = (await host.toolServer.client.callTool({ name: 'send_payment', arguments: args, ...(env !== undefined ? { _meta: { [INTENT_META_KEY]: env } } : {}) })) as { isError?: boolean };
      return { isError: r.isError, entry: (await host.log()).verifier.at(-1)! };
    };

    it('without a proof: refused', async () => {
      const r = await send({ recipient: addr(ATTACKER_ACCOUNT), amount: '2980000000' });
      expect(r.isError).toBe(true);
      expect(r.entry).toMatchObject({ outcome: 'rejected', reason: 'missing_proof' });
    });

    it('with a garbled envelope: refused', async () => {
      const r = await send({ recipient: addr(ATTACKER_ACCOUNT), amount: '2980000000' }, { v: 1, target: 'noir-recursive' });
      expect(r.entry).toMatchObject({ outcome: 'rejected', reason: 'malformed_envelope' });
    });

    it('with a valid proof moved onto a different payment: refused, the proof binds the action', async () => {
      const r = await send({ ...payment, recipient: addr(ATTACKER_ACCOUNT) }, encodeEnvelope(envelope));
      expect(r.entry).toMatchObject({ outcome: 'rejected', reason: 'invalid_proof' });
      const inflated = await send({ ...payment, amount: '48750000000' }, encodeEnvelope(envelope));
      expect(inflated.entry).toMatchObject({ outcome: 'rejected', reason: 'invalid_proof' });
    });

    it('with the proof tampered: refused', async () => {
      const proof = new Uint8Array(envelope.proof);
      proof[proof.length - 40]! ^= 1;
      const r = await send(payment, encodeEnvelope({ ...envelope, proof }));
      expect(r.entry).toMatchObject({ outcome: 'rejected', reason: 'invalid_proof' });
    });

    it('with the proof untouched, for its own payment: executed (control)', async () => {
      const r = await send(payment, encodeEnvelope(envelope));
      expect(r.isError).toBeFalsy();
      expect(r.entry).toMatchObject({ outcome: 'executed', proofBytes: 14_656 });
    });

    it('the same proof again: refused as a replay', async () => {
      const r = await send(payment, encodeEnvelope(envelope));
      expect(r.entry).toMatchObject({ outcome: 'rejected', reason: 'replayed' });
    });

    it('exactly one payment moved money, the controlled one', async () => {
      const { ledger } = await host.log();
      expect(ledger).toHaveLength(ledgerSize + 1);
      expect(ledger.at(-1)).toMatchObject({ recipient: PAYEES.fabrikam.account, amount: '100000000' });
    });
  });
});

describe('anti-stub: the same run under a permissive policy lets the attacks through', () => {
  let host: Host;
  let auth: SoftAuthenticator;
  afterAll(async () => host?.stop());

  it('with the attacker allowlisted and a 50,000 USDC limit, the treasury executes both', async () => {
    ({ host, auth } = await startHost());
    const policy = { ...presetPolicy(), maxAmountUsdc: '50000', payees: [...presetPolicy().payees, ATTACKER_ACCOUNT] };
    await setUpDemo(host, auth, policy);
    const run = await host.runDemo();
    const ps = payments(run);
    expect(ps.map((p) => p.verifier?.outcome)).toEqual(['executed', 'executed', 'executed', 'executed']);
    expect((await host.log()).ledger.map((l) => l.recipient)).toContain(ATTACKER_ACCOUNT);
  });
});

describe('without the precheck, the circuit itself refuses', () => {
  let host: Host;
  let auth: SoftAuthenticator;
  let wire: Wire;
  afterAll(async () => host?.stop());

  it('the attacks fail in proving, with the circuit assertion that refused them', async () => {
    ({ host, auth, wire } = await startHost({ precheck: false }));
    await setUpDemo(host, auth);
    const run = await host.runDemo();
    const [legit, redirect, inflate, legit2] = payments(run);
    expect(legit!.verifier?.outcome).toBe('executed');
    expect(legit2!.verifier?.outcome).toBe('executed');
    expect(redirect!.firewall).toMatchObject({ allowed: false });
    expect(inflate!.firewall).toMatchObject({ allowed: false, reason: 'circuit_rejected', assertion: 'amount exceeds policy limit' });
    for (const p of [redirect!, inflate!]) expect(forwardedCalls(wire, p.callId)).toHaveLength(0);
    expect((await host.log()).ledger).toHaveLength(2);
  });
});
