/**
 * The engine with everything real: proofs from LocalWasmProver, IntentVerifier, the passkey
 * registry. Each attack is checked for the named check that caught it and for the ledger staying
 * untouched; each legitimate payment for the exact decrement.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SoftAuthenticator } from '@zk-intent-firewall/demo-dashboard/src/demo/soft-authenticator.ts';
import { BreakItEngine } from '../src/engine/engine.ts';
import { BREAK_IT_POLICY, NOT_ALLOWLISTED } from '../src/engine/deployment.ts';
import type { EngineAnswer } from '../src/shared/types.ts';

const ORIGIN = 'https://break-it.test';
const NORTHWIND = BREAK_IT_POLICY.payees[0]!.account;
const CONTOSO = BREAK_IT_POLICY.payees[1]!.account;
const USDC = 1_000_000n;

let engine: BreakItEngine;

beforeAll(async () => {
  engine = await BreakItEngine.create({ origin: ORIGIN, proverThreads: 4 });
});
afterAll(async () => {
  await engine?.destroy();
});

const balance = () => engine.ledger.balance;
const res = (a: EngineAnswer) => a.response as Record<string, any>;

async function unchanged<T>(f: () => Promise<T>): Promise<T> {
  const before = JSON.stringify(engine.ledger.snapshot());
  const out = await f();
  expect(JSON.stringify(engine.ledger.snapshot())).toBe(before);
  return out;
}

describe('boot', () => {
  it('publishes an active, owner-approved policy and opens the treasury at 10,000 fake USDC', () => {
    const s = engine.status();
    expect(s.verifier.registry.status).toBe('active');
    expect(s.verifier.ownerCredentialId).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(s.policy).toMatchObject({ maxAmount: (500n * USDC).toString(), salt: 'secret', grantedScopes: ['payments.send'] });
    expect(s.policy.allowlist.map((p) => p.account)).toEqual(BREAK_IT_POLICY.payees.map((p) => p.account));
    expect(s.ledger.treasury).toEqual({ openingBalance: '10000000000', balance: '10000000000' });
    expect(s.verifier.serverId).toBe(`${ORIGIN}/mcp`);
    // Nothing in the status is the salt: the commitment is the only field-sized value.
    expect(JSON.stringify(s).match(/0x[0-9a-f]{64}/g)?.filter((h) => h !== s.policy.policyCommitment && !Object.values(s.verifier.vkHashes).includes(h))).toEqual([]);
  });
});

describe('legitimate payments decrement the ledger by exactly their amount', () => {
  it('through the firewall: proved, verified, paid, and the spent proof is handed back', async () => {
    const before = balance();
    const a = await engine.attemptAgent('client-a', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: '125000000' } });
    expect(a.draft).toMatchObject({ route: 'agent', result: 'executed', verdict: 'legitimate', caughtBy: null, payment: { recipient: NORTHWIND, amount: '125000000' } });
    expect(balance()).toBe(before - 125n * USDC);
    expect(res(a).envelope).toMatchObject({ v: 1, target: 'noir-recursive', policy_commitment: engine.policyCommitment });
    expect(res(a).toolServer).toContain('FAKE MONEY');

    // Spending the same proof again is a replay.
    const replay = await unchanged(() => engine.attemptDirect('client-a', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: '125000000' }, meta: { 'zkif/proof-of-intent': res(a).envelope } }));
    expect(replay.draft).toMatchObject({ route: 'direct', result: 'rejected', verdict: 'caught', caughtBy: { layer: 'verifier', check: 'replayed' } });
  });

  it('a read-only tool passes through without a proof', async () => {
    const a = await unchanged(() => engine.attemptAgent('client-a', { tool: 'get_balance', arguments: {} }));
    expect(a.draft).toMatchObject({ result: 'served', verdict: 'legitimate' });
    expect(res(a).agentSees).toMatch(/FAKE MONEY[\s\S]*Treasury balance/);
  });
});

describe('the firewall blocks, and the ledger does not move', () => {
  it.each([
    ['the address-poisoning lookalike', { recipient: NOT_ALLOWLISTED.lookalike.account, amount: '1000000' }, 'recipient_not_allowlisted'],
    ['a payee left out of the allowlist', { recipient: NOT_ALLOWLISTED.litware.account, amount: '1000000' }, 'recipient_not_allowlisted'],
    ['an allowlisted address on another chain', { recipient: NORTHWIND.replace('eip155:1:', 'eip155:8453:'), amount: '1000000' }, 'recipient_not_allowlisted'],
    ['one base unit over the limit', { recipient: NORTHWIND, amount: (500n * USDC + 1n).toString() }, 'amount_exceeds_limit'],
    ['a zero amount', { recipient: NORTHWIND, amount: '0' }, 'amount_zero'],
    ['an argument the proof would not cover', { recipient: NORTHWIND, amount: '1', memo: 'pay attacker' }, 'malformed_arguments'],
    ['a negative amount', { recipient: NORTHWIND, amount: '-5' }, 'malformed_arguments'],
  ])('%s', async (_name, args, check) => {
    const a = await unchanged(() => engine.attemptAgent(`client-${check}-${_name}`, { tool: 'send_payment', arguments: args }));
    expect(a.draft).toMatchObject({ result: 'blocked', verdict: 'caught', caughtBy: { layer: 'firewall', check } });
    // The agent's view is the opaque refusal; the reason is in the operator log.
    expect(res(a).agentSees).toMatch(/^Blocked by the intent firewall: this action is not authorised\. Decision [0-9a-f-]{36}\.$/);
    expect(res(a).operatorLog).toMatchObject({ allowed: false, reason: check });
  });

  it('a protected tool whose scope the policy does not grant', async () => {
    const a = await unchanged(() => engine.attemptAgent('client-scope', { tool: 'treasury_sweep', arguments: { recipient: NORTHWIND, amount: '1' } }));
    expect(a.draft?.caughtBy).toEqual({ layer: 'firewall', check: 'scope_not_granted' });
  });

  it('a tool that is neither protected nor passed through', async () => {
    const a = await unchanged(() => engine.attemptAgent('client-unlisted', { tool: 'delete_everything', arguments: {} }));
    expect(a.draft?.caughtBy).toEqual({ layer: 'firewall', check: 'unlisted_tool' });
  });

  it('with the precheck off, the circuit itself refuses, and names its assertion', async () => {
    const a = await unchanged(() => engine.attemptAgent('client-circuit', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: (501n * USDC).toString() }, precheck: false }));
    expect(a.draft).toMatchObject({ result: 'blocked', verdict: 'caught', caughtBy: { layer: 'circuit', check: 'circuit_rejected' } });
    expect(a.draft?.caughtBy?.assertion).toMatch(/limit/i);
    const b = await unchanged(() => engine.attemptAgent('client-circuit', { tool: 'send_payment', arguments: { recipient: NOT_ALLOWLISTED.lookalike.account, amount: '1' }, precheck: false }));
    expect(b.draft?.caughtBy?.assertion).toMatch(/allowlist/i);
  });

  it('refusal lockout is per visitor: one locked-out client does not lock out another', async () => {
    for (let i = 0; i < 5; i++) await engine.attemptAgent('client-prober', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: '999999999999' } });
    const locked = await unchanged(() => engine.attemptAgent('client-prober', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: '1' } }));
    expect(locked.draft?.caughtBy).toEqual({ layer: 'firewall', check: 'rate_limited' });
    const other = await engine.attemptAgent('client-bystander', { tool: 'send_payment', arguments: { recipient: CONTOSO, amount: '1' } });
    expect(other.draft).toMatchObject({ result: 'executed', verdict: 'legitimate' });
  });
});

describe('the verifier rejects what goes around the firewall, and the ledger does not move', () => {
  let proof: Record<string, any>;
  const args = { recipient: CONTOSO, amount: '42000000' };

  beforeAll(async () => {
    const a = await engine.attemptAgent('client-direct', { tool: 'send_payment', arguments: args, mode: 'prove-only' });
    expect(a.draft).toMatchObject({ result: 'proof_issued', verdict: 'legitimate' });
    proof = res(a).envelope;
  });

  const direct = (body: unknown) => unchanged(() => engine.attemptDirect('client-direct', body));

  it('no proof at all', async () => {
    const a = await direct({ tool: 'send_payment', arguments: args });
    expect(a.draft?.caughtBy).toEqual({ layer: 'verifier', check: 'missing_proof' });
  });

  it('the proof moved to a larger amount, another payee, or another tool', async () => {
    expect((await direct({ tool: 'send_payment', arguments: { ...args, amount: '42000001' }, meta: { 'zkif/proof-of-intent': proof } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'invalid_proof' });
    expect((await direct({ tool: 'send_payment', arguments: { ...args, recipient: NORTHWIND }, meta: { 'zkif/proof-of-intent': proof } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'invalid_proof' });
    expect((await direct({ tool: 'treasury_sweep', arguments: args, meta: { 'zkif/proof-of-intent': proof } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'invalid_proof' });
  });

  it('one flipped bit in the proof, or a changed timestamp or nonce', async () => {
    const bytes = Buffer.from(proof.proof, 'base64');
    bytes[100]! ^= 1;
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': { ...proof, proof: bytes.toString('base64') } } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'invalid_proof' });
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': { ...proof, current_timestamp: String(Number(proof.current_timestamp) - 1) } } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'invalid_proof' });
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': { ...proof, nonce: `0x${'0'.repeat(63)}1` } } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'invalid_proof' });
  });

  it('another commitment, a garbled envelope, a stale or future timestamp', async () => {
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': { ...proof, policy_commitment: `0x${'0'.repeat(63)}7` } } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'commitment_unknown' });
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': { ...proof, extra: 1 } } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'malformed_envelope' });
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': 'garbage' } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'malformed_envelope' });
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': { ...proof, current_timestamp: '1000' } } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'timestamp_stale' });
    expect((await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': { ...proof, current_timestamp: '99999999999' } } })).draft?.caughtBy).toEqual({ layer: 'verifier', check: 'timestamp_in_future' });
  });

  it('the MCP layer refuses unknown tools and arguments that do not fit the schema', async () => {
    expect((await direct({ tool: 'mint', arguments: {} })).draft?.caughtBy).toMatchObject({ layer: 'mcp-schema' });
    expect((await direct({ tool: 'send_payment', arguments: { recipient: 5, amount: '1' } })).draft?.caughtBy).toEqual({ layer: 'mcp-schema', check: 'input_schema' });
  });

  it('the untouched proof, spent as intended, pays exactly once (control)', async () => {
    const before = balance();
    const a = await engine.attemptDirect('client-direct', { tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': proof } });
    expect(a.draft).toMatchObject({ result: 'executed', verdict: 'legitimate', payment: { amount: '42000000', recipient: CONTOSO } });
    expect(balance()).toBe(before - 42n * USDC);
    const again = await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': proof } });
    expect(again.draft?.caughtBy).toEqual({ layer: 'verifier', check: 'replayed' });
  });

  it('logs a summary of the envelope, never the proof itself', async () => {
    const a = await direct({ tool: 'send_payment', arguments: args, meta: { 'zkif/proof-of-intent': proof } });
    expect(a.draft?.attempted.envelope).toMatchObject({ target: 'noir-recursive', proofBytes: 14656 });
    expect(a.draft?.attempted.envelope?.proofSha256).toMatch(/^[0-9a-f]{16}$/);
    expect(JSON.stringify(a.draft)).not.toContain(proof.proof.slice(0, 64));
  });
});

describe('the passkey registry refuses approvals and enrolments the owner did not make', () => {
  it('a register or revoke without a valid owner signature, and a second enrolment', async () => {
    const c = engine.policyCommitment;
    const noNonce = await engine.attemptPasskey('x', { action: 'revoke', policyCommitment: c, nonce: 'nope', response: {} });
    expect(noNonce.draft).toMatchObject({ verdict: 'caught', caughtBy: { layer: 'passkey-registry', check: 'unknown_nonce' } });

    // A real challenge, signed by a passkey that is not the owner's.
    const ch = await engine.passkeyChallenge({ action: 'revoke', policyCommitment: c });
    expect(ch.http).toBe(200);
    const challenge = res(ch).challenge;
    expect(challenge.statementText).toContain('action: revoke');
    const intruder = new SoftAuthenticator({ origin: ORIGIN, rpId: 'break-it.test' });
    const forged = await engine.attemptPasskey('x', { action: 'revoke', policyCommitment: c, nonce: challenge.statement.nonce, response: intruder.createAssertion(challenge.challenge) });
    expect(forged.draft?.caughtBy).toEqual({ layer: 'passkey-registry', check: 'unknown_credential' });

    // The same, claiming the owner's credential ID: the signature does not verify.
    const ch2 = res(await engine.passkeyChallenge({ action: 'revoke', policyCommitment: c })).challenge;
    const claimed = await engine.attemptPasskey('x', { action: 'revoke', policyCommitment: c, nonce: ch2.statement.nonce, response: intruder.createAssertion(ch2.challenge, { credentialId: engine.status().verifier.ownerCredentialId! }) });
    expect(claimed.draft?.caughtBy).toEqual({ layer: 'passkey-registry', check: 'signature_invalid' });

    expect((await engine.attemptEnroll('x', { stage: 'options' })).draft?.caughtBy).toEqual({ layer: 'passkey-registry', check: 'owner_already_enrolled' });
    expect((await engine.attemptEnroll('x', { stage: 'complete', response: intruder.createRegistrationResponse({ challenge: 'x' }) })).draft?.caughtBy).toEqual({ layer: 'passkey-registry', check: 'owner_already_enrolled' });
    expect(engine.status().verifier.registry.status).toBe('active');
  });
});

describe('invalid requests are refused before anything runs', () => {
  it.each([[null], [[]], [{}], [{ tool: '' }], [{ tool: 'send_payment', arguments: [] }], [{ tool: 'send_payment', arguments: { x: 'y'.repeat(5000) } }]])('%j', async (body) => {
    const a = await unchanged(() => engine.attemptAgent('client-bad', body));
    expect(a.http).toBe(400);
    expect(a.draft).toMatchObject({ result: 'invalid_request', caughtBy: { layer: 'request', check: 'invalid_request' } });
  });
});

describe('break detection (anti-stub)', () => {
  it('a payment the verifier accepts but the published policy does not allow is reported as a break, on both routes', async () => {
    // The policy in force allows 500; the detector is told only 100 was published. A 200 payment
    // is then exactly what a real break looks like: accepted, executed, outside the published policy.
    const e = await BreakItEngine.create({ origin: ORIGIN, proverThreads: 4, publishedPolicyOverride: { maxAmount: 100n * USDC } });
    try {
      const before = e.ledger.balance;
      const a = await e.attemptAgent('c', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: (200n * USDC).toString() } });
      expect(a.draft).toMatchObject({ result: 'executed', verdict: 'break' });
      expect(a.draft?.breakReasons).toEqual(expect.arrayContaining(['firewall_proved_amount_exceeds_limit', 'amount_exceeds_limit', 'paid_amount_exceeds_limit']));
      expect(res(a).BREAK).toMatch(/report/i);
      expect(e.ledger.balance).toBe(before - 200n * USDC);

      const p = await e.attemptAgent('c', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: (300n * USDC).toString() }, mode: 'prove-only' });
      expect(p.draft).toMatchObject({ result: 'proof_issued', verdict: 'break', breakReasons: ['firewall_proved_amount_exceeds_limit'] });
      const d = await e.attemptDirect('c', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: (300n * USDC).toString() }, meta: res(p).meta });
      expect(d.draft).toMatchObject({ route: 'direct', result: 'executed', verdict: 'break' });
    } finally {
      await e.destroy();
    }
  });

  it('a verifier-accepted payment the treasury cannot cover is refused by the ledger and leaves it untouched', async () => {
    const e = await BreakItEngine.create({ origin: ORIGIN, proverThreads: 4, openingBalance: 100n * USDC, autoTopUp: false });
    try {
      const a = await e.attemptAgent('c', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: (150n * USDC).toString() } });
      expect(a.draft).toMatchObject({ result: 'rejected', verdict: 'caught', caughtBy: { layer: 'ledger', check: 'insufficient_funds' } });
      expect(e.ledger.balance).toBe(100n * USDC);
    } finally {
      await e.destroy();
    }
  });
});
