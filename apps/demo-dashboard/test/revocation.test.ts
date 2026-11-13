/**
 * Revocation takes effect: register a policy with the passkey, pay under it, revoke it with the
 * passkey, then show that the next payment is refused well before the policy's expiry, both by the
 * firewall (which consults the registry) and by the verifier on its own, when handed a proof that
 * is cryptographically valid, fresh and unreplayed.
 *
 * Real processes throughout: host and prover here, tool server (verifier) and sandboxed agent as
 * children.
 */
import { decodeEnvelope, getHasher, INTENT_META_KEY, ProofVerifier, parseField } from '@zk-intent-firewall/mcp-firewall';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { approve, presetPolicy, setUpDemo } from '../src/demo/flow.ts';
import type { SoftAuthenticator } from '../src/demo/soft-authenticator.ts';
import type { Host } from '../src/server/host/host.ts';
import { treasuryCatalog } from '../src/server/tools.ts';
import { PAYEES } from '../src/shared/demo-config.ts';
import { forwardedCalls, payments, startHost, type Wire } from './helpers.ts';

let host: Host;
let auth: SoftAuthenticator;
let wire: Wire;
let proofs: ProofVerifier;

beforeAll(async () => {
  ({ host, auth, wire } = await startHost());
  proofs = await ProofVerifier.create();
});

afterAll(async () => {
  await host?.stop();
  await proofs?.destroy();
});

describe('revocation', () => {
  let commitment: string;
  let expiry: bigint;
  let ledgerBeforeRevocation: number;

  it('register: a passkey-approved policy pays the legitimate invoices', async () => {
    const policy = presetPolicy();
    expiry = policy.expiry;
    const { policy: prepared } = await setUpDemo(host, auth, policy);
    commitment = prepared.policyCommitment;
    expect(await host.policyStatus(commitment)).toBe('active');

    const run = await host.runDemo();
    const paid = payments(run).filter((p) => p.verifier?.outcome === 'executed');
    expect(paid.map((p) => p.recipient.toLowerCase())).toEqual([PAYEES.northwind.account, PAYEES.fabrikam.account].map((a) => a.split(':')[2]));
    ledgerBeforeRevocation = (await host.log()).ledger.length;
    expect(ledgerBeforeRevocation).toBe(2);
  });

  it('revoke: needs a passkey signature over the revoke statement', async () => {
    const r = await approve(host, auth, 'revoke', commitment);
    expect(r).toMatchObject({ ok: true, status: 'revoked' });
    expect(await host.policyStatus(commitment)).toBe('revoked');
    // The policy itself is still well within its validity: only revocation can stop it now.
    expect(expiry - BigInt(Math.floor(Date.now() / 1000))).toBeGreaterThan(29n * 86_400n);
  });

  it('the firewall, consulting the registry, refuses before proving', async () => {
    const run = await host.runDemo();
    const ps = payments(run);
    expect(ps).toHaveLength(4);
    for (const p of ps) {
      expect(p.firewall).toMatchObject({ allowed: false, reason: 'policy_not_active' });
      expect(p.verifier).toBeUndefined();
      expect(forwardedCalls(wire, p.callId)).toHaveLength(0);
    }
    expect((await host.log()).ledger).toHaveLength(ledgerBeforeRevocation);
  });

  it('the verifier refuses a valid, fresh, unexpired proof under the revoked policy', async () => {
    // A firewall that ignores the registry (compromised, stale, or simply wrong) keeps proving.
    const run = await host.runDemo({ firewallChecksRegistry: false });
    const legit = payments(run).filter((p) => p.firewall?.allowed === true);
    expect(legit).toHaveLength(2);

    const hasher = await getHasher();
    const catalog = treasuryCatalog();
    for (const p of legit) {
      expect(p.verifier).toMatchObject({ outcome: 'rejected', reason: 'commitment_revoked' });

      // What the tool server received is a proof that verifies, independently, against the pinned
      // key with the public inputs the verifier itself would build: the registry is the only thing
      // that stopped it.
      const [call] = forwardedCalls(wire, p.callId);
      expect(call).toBeDefined();
      const envelope = decodeEnvelope(call!.params._meta[INTENT_META_KEY]);
      expect(envelope.policyCommitment).toBe(parseField(commitment));
      const binding = hasher.actionBinding({ ...catalog.resolve(call!.params.name, call!.params.arguments), nonce: envelope.nonce });
      expect(await proofs.verify(envelope.target, envelope.proof, [envelope.policyCommitment, envelope.currentTimestamp, binding])).toBe(true);
      // Fresh and before expiry: freshness and the circuit's own expiry check would have passed.
      expect(Math.abs(Number(envelope.currentTimestamp) - Date.now() / 1000)).toBeLessThan(120);
      expect(envelope.currentTimestamp).toBeLessThan(expiry);
    }
    expect((await host.log()).ledger).toHaveLength(ledgerBeforeRevocation);
  });

  it('the same proof, sent straight to the tool server, is still refused', async () => {
    // Bypass the firewall entirely and replay the last forwarded proof under a fresh call id.
    const last = wire.toolServerRequests
      .filter((m): m is { method: string; params: { name: string; arguments: Record<string, unknown>; _meta: Record<string, unknown> } } => (m as { method?: string }).method === 'tools/call' && (m as { params: { name: string } }).params.name === 'send_payment')
      .at(-1)!;
    const result = (await host.toolServer.client.callTool({ name: 'send_payment', arguments: last.params.arguments, _meta: { [INTENT_META_KEY]: last.params._meta[INTENT_META_KEY] } })) as {
      isError?: boolean;
    };
    expect(result.isError).toBe(true);
    const entry = (await host.log()).verifier.at(-1)!;
    expect(entry).toMatchObject({ outcome: 'rejected', reason: 'commitment_revoked' });
    expect((await host.log()).ledger).toHaveLength(ledgerBeforeRevocation);
  });

  it('cannot be undone: the verifier will not even issue a registration challenge for it', async () => {
    // (A signed registration approval for a revoked commitment is refused too: passkey-registry.test.ts.)
    await expect(approve(host, auth, 'register', commitment)).rejects.toThrow(/revoked/);
    expect(await host.policyStatus(commitment)).toBe('revoked');
  });
});
