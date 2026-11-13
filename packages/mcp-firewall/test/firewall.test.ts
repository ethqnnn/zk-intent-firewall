/**
 * The firewall end to end over MCP. Every rejection path of the circuit's test suite has an
 * equivalent here, and in each one the call is BLOCKED before it reaches the tool handler: the
 * ledger stays empty and the handler never runs.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { CIRCUIT_ASSERTIONS } from '../src/circuit.js';
import { fieldToHex } from '../src/crypto/field.js';
import { toField } from '../src/crypto/identifiers.js';
import { decodeEnvelope, encodeEnvelope, INTENT_META_KEY } from '../src/envelope.js';
import type { BlockReason } from '../src/firewall.js';
import type { Prover } from '../src/prover/types.js';
import { ToolCatalog, transferTool } from '../src/tools.js';
import { SCENARIO, vectors } from './fixtures.js';
import { ACCOUNTS, ATTACKER, createHarness, createShared, destroyShared, type Harness, type HarnessOptions, isBlocked, isRejected, type Shared, SCOPES, TOOL_SPECS } from './harness.js';

let shared: Shared;
let h: Harness | undefined;
beforeAll(async () => {
  shared = await createShared();
});
afterAll(async () => {
  await destroyShared(shared);
});
afterEach(async () => {
  await h?.close();
  h = undefined;
});

const setup = async (o: HarnessOptions = {}) => (h = await createHarness(shared, o));
const pay = (tool: string, recipient: string, amount: string | number) => h!.agent.callTool({ name: tool, arguments: { recipient, amount } });
const lastDecision = () => h!.decisions.at(-1)!;

/** Nothing was paid and no protected handler ran. */
function expectNothingExecuted() {
  expect(h!.ledger).toEqual([]);
  expect(h!.handlerCalls.filter((c) => c !== 'read_invoice')).toEqual([]);
}

describe('allowed', () => {
  it('a valid payment is proven, verified by the server and executed', async () => {
    await setup();
    const r = await pay('send_payment', ACCOUNTS[3]!, '125000000');
    expect(r.isError).toBeFalsy();
    expect(h!.ledger).toEqual([{ tool: 'send_payment', recipient: ACCOUNTS[3], amount: '125000000' }]);
    expect(h!.rejections).toEqual([]);
    expect(lastDecision()).toMatchObject({ allowed: true, toolName: 'send_payment' });
    // The server saw a proof, and nothing about the policy.
    const env = h!.receivedMeta[0]![INTENT_META_KEY] as Record<string, unknown>;
    expect(Object.keys(env).sort()).toEqual(['current_timestamp', 'nonce', 'policy_commitment', 'proof', 'target', 'v']);
  });

  it('with the fixture nonce and clock, the firewall proves exactly the fixture public inputs', async () => {
    await setup({ firewall: { nonceSource: () => toField('zkif.fixture.v1', 'nonce-0001') } });
    const auth = await h!.firewall.authorize('send_payment', { recipient: ACCOUNTS[3], amount: '125000000' });
    expect(auth.allowed && auth.protected).toBe(true);
    if (!auth.allowed || !auth.protected) return;
    expect(fieldToHex(h!.policy.commitment)).toBe(vectors.policy_commitment);
    expect(fieldToHex(auth.action.toolId)).toBe(vectors.action.tool_id);
    expect(fieldToHex(auth.action.recipient)).toBe(vectors.action.recipient);
    expect(auth.envelope.currentTimestamp.toString()).toBe(vectors.current_timestamp);
    const binding = shared.hasher.actionBinding(auth.action);
    expect([auth.envelope.policyCommitment, auth.envelope.currentTimestamp, binding].map(fieldToHex)).toEqual(vectors.public_inputs);
    expect(await shared.serverSideVerifier.verify('noir-recursive', auth.envelope.proof, [auth.envelope.policyCommitment, auth.envelope.currentTimestamp, binding])).toBe(true);
  });

  it('the evm target works end to end', async () => {
    await setup({ firewall: { target: 'evm' } });
    expect((await pay('send_payment', ACCOUNTS[0]!, 1)).isError).toBeFalsy();
    expect(h!.ledger).toHaveLength(1);
  });

  it('boundaries: exactly the limit, the last second before expiry', async () => {
    await setup();
    h!.firewallClock.now = h!.serverClock.now = SCENARIO.expiry - 1n;
    expect((await pay('refund_payment', ACCOUNTS[4]!, SCENARIO.maxAmount.toString())).isError).toBeFalsy();
    expect(h!.ledger).toEqual([{ tool: 'refund_payment', recipient: ACCOUNTS[4], amount: '500000000' }]);
  });

  it('an explicitly passed-through read-only tool needs no proof', async () => {
    await setup();
    const r = await h!.agent.callTool({ name: 'read_invoice', arguments: { invoice_id: 'INV-42' } });
    expect(r.isError).toBeFalsy();
    expect(h!.handlerCalls).toEqual(['read_invoice']);
  });
});

/** The firewall stopped the call itself: it was never forwarded to the server. */
function expectNeverForwarded(tool: string) {
  expect(h!.forwarded.filter((t) => t === tool)).toEqual([]);
  expectNothingExecuted();
}

describe('blocked by the firewall: each circuit rejection path', () => {
  // [name, call, pre-check reason, circuit assertion with the pre-check off]
  const cases: [string, () => ReturnType<typeof pay>, BlockReason, string, (() => void)?][] = [
    ['recipient not on the allowlist', () => pay('send_payment', ATTACKER, '1000'), 'recipient_not_allowlisted', CIRCUIT_ASSERTIONS.C2b],
    ['same account on another network', () => h!.agent.callTool({ name: 'send_payment', arguments: { recipient: 'eip155:137:' + ACCOUNTS[3]!.split(':')[2], amount: '1' } }), 'recipient_not_allowlisted', CIRCUIT_ASSERTIONS.C2b],
    ['amount over the limit', () => pay('send_payment', ACCOUNTS[3]!, (SCENARIO.maxAmount + 1n).toString()), 'amount_exceeds_limit', CIRCUIT_ASSERTIONS.C3b],
    ['zero amount', () => pay('send_payment', ACCOUNTS[3]!, '0'), 'amount_zero', CIRCUIT_ASSERTIONS.C3a],
    ['expired policy', () => pay('send_payment', ACCOUNTS[3]!, '1'), 'policy_expired', CIRCUIT_ASSERTIONS.C5, () => (h!.firewallClock.now = SCENARIO.expiry)],
    ['scope not granted', () => pay('sweep_treasury', ACCOUNTS[0]!, '1'), 'scope_not_granted', CIRCUIT_ASSERTIONS.C4b],
  ];

  describe.each([true, false])('pre-check %s', (precheck) => {
    it.each(cases)('%s', async (_name, call, reason, assertion, before) => {
      await setup({ firewall: { precheck } });
      before?.();
      const r = await call();
      expect(isBlocked(r)).toBe(true);
      expect(h!.forwarded).toEqual([]);
      expectNothingExecuted();
      const d = lastDecision();
      expect(d.allowed).toBe(false);
      if (precheck) expect(d.reason).toBe(reason);
      else expect([d.reason, d.assertion]).toEqual(['circuit_rejected', assertion]);
    });
  });

  it('the agent learns nothing about why', async () => {
    await setup();
    const a = await pay('send_payment', ATTACKER, '1');
    const b = await pay('send_payment', ACCOUNTS[3]!, '999999999999');
    const strip = (r: unknown) => JSON.stringify(r).replace(/Decision [0-9a-f-]+/, '');
    expect(strip(a)).toBe(strip(b));
    expect(JSON.stringify(a)).not.toMatch(/allowlist|limit|scope|expire|amount/i);
  });

  it('missing scope: the firewall believes the tool needs a granted scope, the server knows it needs another', async () => {
    // The firewall's definition of sweep_treasury says scope 3 (granted); the server's says 5.
    const lying = TOOL_SPECS.map((s) => (s.name === 'sweep_treasury' ? transferTool({ name: 'sweep_treasury', scope: 'payments.send', assetId: SCENARIO.assetId }) : s));
    await setup({ firewallTools: lying });
    const r = await pay('sweep_treasury', ACCOUNTS[0]!, '1');
    expect(isRejected(r)).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'sweep_treasury', reason: 'invalid_proof' }]);
    expectNothingExecuted();
  });

  it('a tool definition with a scope missing from the registry is a configuration error', () => {
    const tools = [transferTool({ name: 'x', scope: 'payments.nope', assetId: SCENARIO.assetId })];
    expect(() => new ToolCatalog({ serverId: SCENARIO.serverId, tools, scopes: SCOPES })).toThrow(/unknown scope/);
    expect(() => new ToolCatalog({ serverId: SCENARIO.serverId, tools: [transferTool({ name: 'y', scope: 64, assetId: SCENARIO.assetId })] })).toThrow(/unknown scope/);
  });

  it('malformed arguments are blocked, never defaulted', async () => {
    await setup();
    for (const args of [{ recipient: ACCOUNTS[3] }, { amount: '1' }, { recipient: ACCOUNTS[3], amount: 1.5 }, { recipient: ACCOUNTS[3], amount: 2 ** 60 }, { recipient: ACCOUNTS[3], amount: '-1' }]) {
      const r = await h!.agent.callTool({ name: 'send_payment', arguments: args });
      expect(isBlocked(r)).toBe(true);
    }
    expect(h!.decisions.every((d) => d.reason === 'malformed_arguments' || d.reason === 'rate_limited')).toBe(true);
    expectNeverForwarded('send_payment');
  });

  it('an unlisted tool is blocked by default', async () => {
    await setup();
    expect(isBlocked(await h!.agent.callTool({ name: 'delete_account', arguments: {} }))).toBe(true);
    expect(lastDecision().reason).toBe('unlisted_tool');
    expect(h!.forwarded).toEqual([]);
    expect(h!.handlerCalls).toEqual([]);
  });
});

describe('tampered binding', () => {
  it('a prover whose binding disagrees with the action is stopped by the circuit (C6)', async () => {
    const tampering = (p: Prover): Prover => ({
      name: 'tampering',
      prove: (req) => p.prove({ ...req, inputs: { ...req.inputs, actionBinding: req.inputs.actionBinding ^ 1n } }),
      destroy: () => p.destroy(),
    });
    await setup({ wrapProver: tampering });
    expect(isBlocked(await pay('send_payment', ACCOUNTS[3]!, '125000000'))).toBe(true);
    expect([lastDecision().reason, lastDecision().assertion]).toEqual(['circuit_rejected', CIRCUIT_ASSERTIONS.C6]);
    expectNeverForwarded('send_payment');
  });

  it('a prover that returns a valid proof of a different action is caught by self-verification', async () => {
    const substituting = (p: Prover): Prover => ({
      name: 'substituting',
      async prove(req) {
        const action = { ...req.inputs.action, amount: 1n };
        const proof = await p.prove({ ...req, inputs: { ...req.inputs, action, actionBinding: shared.hasher.actionBinding(action) } });
        return { ...proof, publicInputs: [req.inputs.policyCommitment, req.inputs.currentTimestamp, req.inputs.actionBinding] };
      },
      destroy: () => p.destroy(),
    });
    await setup({ wrapProver: substituting });
    expect(isBlocked(await pay('send_payment', ACCOUNTS[3]!, '125000000'))).toBe(true);
    expect(lastDecision().reason).toBe('self_verification_failed');
    expectNeverForwarded('send_payment');
  });

  it.each([
    ['amount raised', (a: Record<string, unknown>) => (a.amount = '500000000')],
    ['recipient redirected', (a: Record<string, unknown>) => (a.recipient = ATTACKER)],
    ['recipient moved to another allowlisted account', (a: Record<string, unknown>) => (a.recipient = ACCOUNTS[0])],
  ])('an attacker between firewall and server: %s', async (_n, mutate) => {
    await setup({ tamper: (p) => p.name === 'send_payment' && mutate(p.arguments!) });
    expect(isRejected(await pay('send_payment', ACCOUNTS[3]!, '1000'))).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'send_payment', reason: 'invalid_proof' }]);
    expectNothingExecuted();
  });

  it('an attacker who swaps the nonce or timestamp in the envelope', async () => {
    let field: 'nonce' | 'current_timestamp' = 'nonce';
    await setup({
      tamper: (p) => {
        const env = p._meta![INTENT_META_KEY] as Record<string, string>;
        if (field === 'nonce') env.nonce = fieldToHex(BigInt(env.nonce!) ^ 1n);
        else env.current_timestamp = (BigInt(env.current_timestamp!) - 1n).toString();
      },
    });
    expect(isRejected(await pay('send_payment', ACCOUNTS[3]!, '1000'))).toBe(true);
    field = 'current_timestamp';
    expect(isRejected(await pay('send_payment', ACCOUNTS[3]!, '1000'))).toBe(true);
    expect(h!.rejections.map((r) => r.reason)).toEqual(['invalid_proof', 'invalid_proof']);
    expectNothingExecuted();
  });
});

describe("the verifier's off-circuit obligations", () => {
  /** Lets one valid call through and returns its exact _meta, as an eavesdropper would see it. */
  async function captureValidCall(recipient = ACCOUNTS[3]!, amount = '1000') {
    await pay('send_payment', recipient, amount);
    expect(h!.ledger).toHaveLength(1);
    return { meta: h!.receivedMeta[0]!, args: { recipient, amount } };
  }

  it('a call that bypasses the firewall has no proof and is rejected', async () => {
    await setup();
    const direct = await h!.direct();
    expect(isRejected(await direct.callTool({ name: 'send_payment', arguments: { recipient: ACCOUNTS[3]!, amount: '1' } }))).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'send_payment', reason: 'missing_proof' }]);
    expectNothingExecuted();
  });

  it('a replayed call is rejected', async () => {
    await setup();
    const { meta, args } = await captureValidCall();
    const direct = await h!.direct();
    expect(isRejected(await direct.callTool({ name: 'send_payment', arguments: args, _meta: meta }))).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'send_payment', reason: 'replayed' }]);
    expect(h!.ledger).toHaveLength(1);
  });

  it('two identical concurrent submissions of one proof execute once', async () => {
    await setup();
    const args = { recipient: ACCOUNTS[3]!, amount: '1000' };
    const auth = await h!.firewall.authorize('send_payment', args);
    if (!auth.allowed || !auth.protected) throw new Error('expected an allowed call');
    const m = { [INTENT_META_KEY]: encodeEnvelope(auth.envelope) };
    const [c1, c2] = [await h!.direct(), await h!.direct()];
    const rs = await Promise.all([c1.callTool({ name: 'send_payment', arguments: args, _meta: m }), c2.callTool({ name: 'send_payment', arguments: args, _meta: m })]);
    expect(rs.filter((r) => !r.isError)).toHaveLength(1);
    expect(h!.ledger).toHaveLength(1);
    expect(h!.rejections).toEqual([{ tool: 'send_payment', reason: 'replayed' }]);
  });

  it('a stale timestamp is rejected, and so is one from the future', async () => {
    await setup();
    h!.firewallClock.now = SCENARIO.now - 61n;
    expect(isRejected(await pay('send_payment', ACCOUNTS[3]!, '1'))).toBe(true);
    h!.firewallClock.now = SCENARIO.now + 6n;
    expect(isRejected(await pay('send_payment', ACCOUNTS[3]!, '1'))).toBe(true);
    h!.firewallClock.now = SCENARIO.now - 60n;
    expect((await pay('send_payment', ACCOUNTS[3]!, '1')).isError).toBeFalsy();
    expect(h!.rejections.map((r) => r.reason)).toEqual(['timestamp_stale', 'timestamp_in_future']);
    expect(h!.ledger).toHaveLength(1);
  });

  it('a revoked commitment is rejected by the server even though the proof is valid', async () => {
    await setup();
    h!.registry.revoke(h!.policy.commitment, 'owner revoked');
    expect(isRejected(await pay('send_payment', ACCOUNTS[3]!, '1'))).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'send_payment', reason: 'commitment_revoked' }]);
    expect(() => h!.registry.register(h!.policy.commitment)).toThrow(/revoked/);
    expectNothingExecuted();
  });

  it('a firewall that consults the registry refuses to prove under a revoked commitment', async () => {
    await setup();
    const { registry } = h!;
    await h!.close();
    await setup({ firewall: { registry } });
    registry.revoke(h!.policy.commitment);
    expect(isBlocked(await pay('send_payment', ACCOUNTS[3]!, '1'))).toBe(true);
    expect(lastDecision().reason).toBe('policy_not_active');
    expectNeverForwarded('send_payment');
  });

  it('an unregistered commitment is rejected', async () => {
    await setup();
    const direct = await h!.direct();
    const auth = await h!.firewall.authorize('send_payment', { recipient: ACCOUNTS[3], amount: '1' });
    if (!auth.allowed || !auth.protected) throw new Error('expected an allowed call');
    const env = { ...encodeEnvelope(auth.envelope), policy_commitment: fieldToHex(1n) };
    expect(isRejected(await direct.callTool({ name: 'send_payment', arguments: { recipient: ACCOUNTS[3]!, amount: '1' }, _meta: { [INTENT_META_KEY]: env } }))).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'send_payment', reason: 'commitment_unknown' }]);
  });

  it('a proof made for another server is rejected (tool_id commits to the server)', async () => {
    await setup({ firewallServerId: 'https://evil.example.com/mcp' });
    expect(isRejected(await pay('send_payment', ACCOUNTS[3]!, '1'))).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'send_payment', reason: 'invalid_proof' }]);
  });

  it('a proof for one tool is not accepted for another', async () => {
    await setup();
    const direct = await h!.direct();
    const auth = await h!.firewall.authorize('send_payment', { recipient: ACCOUNTS[3], amount: '1' });
    if (!auth.allowed || !auth.protected) throw new Error('expected an allowed call');
    const meta = { [INTENT_META_KEY]: encodeEnvelope(auth.envelope) };
    expect(isRejected(await direct.callTool({ name: 'refund_payment', arguments: { recipient: ACCOUNTS[3]!, amount: '1' }, _meta: meta }))).toBe(true);
    expect(h!.rejections).toEqual([{ tool: 'refund_payment', reason: 'invalid_proof' }]);
  });

  it('an envelope the agent supplies itself is discarded by the firewall', async () => {
    await setup();
    const forged = { v: 1, target: 'noir-recursive', policy_commitment: fieldToHex(h!.policy.commitment), current_timestamp: '1', nonce: fieldToHex(1n), proof: '' };
    await h!.agent.callTool({ name: 'read_invoice', arguments: { invoice_id: 'INV-42' }, _meta: { [INTENT_META_KEY]: forged } });
    await h!.agent.callTool({ name: 'send_payment', arguments: { recipient: ACCOUNTS[3]!, amount: '1' }, _meta: { [INTENT_META_KEY]: forged } });
    expect(h!.ledger).toHaveLength(1);
    // Removed from the pass-through call, replaced by the firewall's own on the protected one.
    expect(h!.readOnlyMeta[0]![INTENT_META_KEY]).toBeUndefined();
    const env = decodeEnvelope(h!.receivedMeta[0]![INTENT_META_KEY]);
    expect(env.currentTimestamp).toBe(SCENARIO.now);
  });

  it('malformed envelopes are rejected', async () => {
    await setup();
    const direct = await h!.direct();
    const args = { recipient: ACCOUNTS[3]!, amount: '1' };
    for (const env of [null, 'x', { v: 1 }, { v: 2, target: 'noir-recursive', policy_commitment: '0x1', current_timestamp: '1', nonce: '0x1', proof: '' }, { v: 1, target: 'evm-no-zk', policy_commitment: '0x1', current_timestamp: '1', nonce: '0x1', proof: '' }]) {
      expect(isRejected(await direct.callTool({ name: 'send_payment', arguments: args, _meta: { [INTENT_META_KEY]: env } }))).toBe(true);
    }
    expect(h!.rejections.every((r) => r.reason === 'malformed_envelope')).toBe(true);
    expectNothingExecuted();
  });
});

describe('refusal rate limit (spec L10)', () => {
  it('locks protected calls after repeated refusals, then recovers', async () => {
    await setup({ firewall: { refusalLimit: { maxRefusals: 3, windowSeconds: 60n, lockoutSeconds: 120n } } });
    for (let i = 0; i < 3; i++) await pay('send_payment', ACCOUNTS[3]!, String(SCENARIO.maxAmount + 1n + BigInt(i)));
    expect(isBlocked(await pay('send_payment', ACCOUNTS[3]!, '1'))).toBe(true);
    expect(lastDecision().reason).toBe('rate_limited');
    expect(h!.forwarded).toEqual([]);
    h!.firewallClock.now += 120n;
    h!.serverClock.now += 120n;
    expect((await pay('send_payment', ACCOUNTS[3]!, '1')).isError).toBeFalsy();
    expect(h!.ledger).toHaveLength(1);
  });
});
