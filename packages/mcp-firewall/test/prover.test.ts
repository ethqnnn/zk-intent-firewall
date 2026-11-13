/**
 * LocalWasmProver and ProofVerifier against the fixture: a real proof, real verification, the
 * pinned keys, and every circuit assertion surfacing by name.
 */
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { BackendType, Barretenberg } from '@aztec/bb.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  CIRCUIT_ASSERTIONS,
  type CircuitInputs,
  loadCircuit,
  loadVerificationKey,
  PINNED_VERIFICATION_KEYS,
  proofSettings,
  type PublicInputs,
  toInputMap,
  VERIFIER_TARGETS,
} from '../src/circuit.js';
import { fieldToHex } from '../src/crypto/field.js';
import { ProtocolHasher } from '../src/crypto/hash.js';
import { LocalWasmProver } from '../src/prover/local-wasm.js';
import { type IntentProof, ProofGenerationError } from '../src/prover/types.js';
import { ProofVerifier } from '../src/verifier/proof-verifier.js';
import { actionFromJson, policyFromJson, vectors, vkHashes } from './fixtures.js';

const fixtureInputs: CircuitInputs = {
  policyCommitment: BigInt(vectors.policy_commitment),
  currentTimestamp: BigInt(vectors.current_timestamp),
  actionBinding: BigInt(vectors.action_binding),
  policy: policyFromJson(vectors.policy),
  action: actionFromJson(vectors.action),
  leafIndex: Number(vectors.merkle_witness.leaf_index),
  merklePath: vectors.merkle_witness.merkle_path.map(BigInt),
};

let prover: LocalWasmProver;
let verifier: ProofVerifier;
let hasher: ProtocolHasher;
const proofs = new Map<string, IntentProof>();

beforeAll(async () => {
  [prover, verifier, hasher] = await Promise.all([LocalWasmProver.create(), ProofVerifier.create(), ProtocolHasher.create()]);
  for (const target of VERIFIER_TARGETS) proofs.set(target, await prover.prove({ inputs: fixtureInputs, target }));
});
afterAll(async () => {
  await Promise.all([prover?.destroy(), verifier?.destroy()]);
});

describe('pinned circuit and keys', () => {
  it('the input map is the fixture Prover.toml', () => {
    const m = toInputMap(fixtureInputs);
    expect(m).toEqual({
      policy_commitment: vectors.policy_commitment,
      current_timestamp: vectors.current_timestamp,
      action_binding: vectors.action_binding,
      policy: vectors.policy,
      action: vectors.action,
      leaf_index: vectors.merkle_witness.leaf_index,
      merkle_path: vectors.merkle_witness.merkle_path,
    });
  });

  it.each(VERIFIER_TARGETS)('%s: the key file is what bb.js computes, and its hash is the one in vk_hashes.txt', async (target) => {
    expect(PINNED_VERIFICATION_KEYS[target].bbHash).toBe(vkHashes[target]);
    const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
    try {
      const bytecode = gunzipSync(Buffer.from(loadCircuit().bytecode, 'base64'));
      const { bytes, hash } = await api.circuitComputeVk({ circuit: { name: 'proof_of_intent', bytecode }, settings: proofSettings(target) });
      expect(fieldToHex(BigInt('0x' + Buffer.from(hash).toString('hex')))).toBe(vkHashes[target]);
      expect(Buffer.compare(Buffer.from(bytes), Buffer.from(loadVerificationKey(target)))).toBe(0);
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(PINNED_VERIFICATION_KEYS[target].sha256);
    } finally {
      await api.destroy();
    }
  });

  it('no target without zero knowledge is accepted', () => {
    expect(() => proofSettings('evm-no-zk' as never)).toThrow();
    for (const t of VERIFIER_TARGETS) expect(proofSettings(t).disableZk).toBe(false);
  });
});

describe.each(VERIFIER_TARGETS)('%s round trip', (target) => {
  const flip = (x: bigint) => x ^ 1n;

  it('the proof is for the fixture public inputs and verifies', async () => {
    const p = proofs.get(target)!;
    expect(p.publicInputs.map(fieldToHex)).toEqual(vectors.public_inputs);
    expect(await verifier.verify(target, p.proof, p.publicInputs)).toBe(true);
  });

  it.each([0, 1, 2])('a changed public input %i is rejected', async (i) => {
    const p = proofs.get(target)!;
    const pis = [...p.publicInputs] as [bigint, bigint, bigint];
    pis[i] = flip(pis[i]!);
    expect(await verifier.verify(target, p.proof, pis)).toBe(false);
  });

  it('a changed, truncated or empty proof is rejected', async () => {
    const p = proofs.get(target)!;
    const bad = Uint8Array.from(p.proof);
    bad[bad.length >> 1]! ^= 1;
    expect(await verifier.verify(target, bad, p.publicInputs)).toBe(false);
    expect(await verifier.verify(target, p.proof.subarray(0, p.proof.length - 32), p.publicInputs)).toBe(false);
    expect(await verifier.verify(target, new Uint8Array(0), p.publicInputs)).toBe(false);
  });

  it('a proof is not accepted under the other target', async () => {
    const other = VERIFIER_TARGETS.find((t) => t !== target)!;
    const p = proofs.get(target)!;
    expect(await verifier.verify(other, p.proof, p.publicInputs)).toBe(false);
  });
});

describe('witness generation refuses inputs outside the policy, naming the assertion', () => {
  const withAction = (patch: Partial<CircuitInputs['action']>): CircuitInputs => {
    const action = { ...fixtureInputs.action, ...patch };
    return { ...fixtureInputs, action, actionBinding: hasher.actionBinding(action) };
  };
  const withPolicy = (patch: Partial<CircuitInputs['policy']>): CircuitInputs => {
    const policy = { ...fixtureInputs.policy, ...patch };
    return { ...fixtureInputs, policy, policyCommitment: hasher.policyCommitment(policy) };
  };

  const cases: [string, () => CircuitInputs, string][] = [
    ['C1a zero salt', () => withPolicy({ salt: 0n }), CIRCUIT_ASSERTIONS.C1a],
    ['C1b wrong commitment', () => ({ ...fixtureInputs, policyCommitment: fixtureInputs.policyCommitment ^ 1n }), CIRCUIT_ASSERTIONS.C1b],
    ['C2b recipient off the list', () => withAction({ recipient: 0xc7df553d4bf15854f17ad3e244ff85f79d212954d5e2909d407e8cb4dccb00n }), CIRCUIT_ASSERTIONS.C2b],
    ['C3a zero amount', () => withAction({ amount: 0n }), CIRCUIT_ASSERTIONS.C3a],
    ['C3b amount over the limit', () => withAction({ amount: fixtureInputs.policy.maxAmount + 1n }), CIRCUIT_ASSERTIONS.C3b],
    ['C4a scope index 64', () => withAction({ scopeIndex: 64 }), CIRCUIT_ASSERTIONS.C4a],
    ['C4b scope not granted', () => withAction({ scopeIndex: 4 }), CIRCUIT_ASSERTIONS.C4b],
    ['C5 expired', () => ({ ...fixtureInputs, currentTimestamp: fixtureInputs.policy.expiry }), CIRCUIT_ASSERTIONS.C5],
    ['C6 tampered binding', () => ({ ...fixtureInputs, actionBinding: fixtureInputs.actionBinding ^ 1n }), CIRCUIT_ASSERTIONS.C6],
  ];

  it.each(cases)('%s', async (_name, make, assertion) => {
    const err = await prover.prove({ inputs: make(), target: 'noir-recursive' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProofGenerationError);
    expect((err as ProofGenerationError).stage).toBe('witness');
    expect((err as ProofGenerationError).assertion).toBe(assertion);
  });

  it('values outside their integer type never reach the circuit', async () => {
    const err = await prover
      .prove({ inputs: { ...fixtureInputs, currentTimestamp: 1n << 64n }, target: 'noir-recursive' })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ProofGenerationError);
    expect((err as ProofGenerationError).assertion).toBeUndefined();
  });

  it('a proof of other inputs does not verify for the fixture public inputs', async () => {
    const inputs = withAction({ amount: 1n });
    const p = await prover.prove({ inputs, target: 'noir-recursive' });
    const fixturePis = proofs.get('noir-recursive')!.publicInputs;
    expect(await verifier.verify('noir-recursive', p.proof, p.publicInputs)).toBe(true);
    expect(await verifier.verify('noir-recursive', p.proof, fixturePis as PublicInputs)).toBe(false);
  });
});
