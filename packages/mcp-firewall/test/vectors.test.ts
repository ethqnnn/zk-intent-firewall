/**
 * Zero drift between this package and the circuit: every value in fixtures/vectors.json is
 * recomputed here from its inputs, with the same code the firewall and the verifier use.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import {
  EMPTY_LEAF,
  LABEL_ACTION_BINDING,
  LABEL_ALLOWLIST_LEAF,
  LABEL_ALLOWLIST_NODE,
  LABEL_POLICY_COMMITMENT,
  MAX_LEAVES,
  POLICY_VERSION,
  SCOPE_BITS,
  TAG_ACTION_BINDING,
  TAG_ALLOWLIST_LEAF,
  TAG_ALLOWLIST_NODE,
  TAG_POLICY_COMMITMENT,
  TREE_DEPTH,
} from '../src/crypto/constants.js';
import { EncodingError, FIELD_MODULUS, fieldToHex, parseField, parseUint } from '../src/crypto/field.js';
import { ProtocolHasher } from '../src/crypto/hash.js';
import { recipientId, toField, toolId } from '../src/crypto/identifiers.js';
import { AllowlistTree } from '../src/crypto/merkle.js';
import { actionFromJson, policyFromJson, SCENARIO, vectors } from './fixtures.js';

let hasher: ProtocolHasher;
beforeAll(async () => {
  hasher = await ProtocolHasher.create();
});

const hex = fieldToHex;

describe('constants', () => {
  it('field modulus', () => {
    expect(hex(FIELD_MODULUS - 1n)).toBe(vectors.constants.largest_field_element);
    expect('0x' + FIELD_MODULUS.toString(16).padStart(64, '0')).toBe(vectors.constants.field_modulus);
  });

  it('scalar constants', () => {
    expect(hex(POLICY_VERSION)).toBe(vectors.constants.policy_version);
    expect(String(TREE_DEPTH)).toBe(vectors.constants.tree_depth);
    expect(String(MAX_LEAVES)).toBe(vectors.constants.max_leaves);
    expect(String(SCOPE_BITS)).toBe(vectors.constants.scope_bits);
    expect(hex(EMPTY_LEAF)).toBe(vectors.constants.empty_leaf);
  });

  it('domain tags: labels and values', () => {
    const t = vectors.constants.domain_tags;
    expect([t.policy_commitment.label, hex(TAG_POLICY_COMMITMENT)]).toEqual([LABEL_POLICY_COMMITMENT, t.policy_commitment.value]);
    expect([t.allowlist_leaf.label, hex(TAG_ALLOWLIST_LEAF)]).toEqual([LABEL_ALLOWLIST_LEAF, t.allowlist_leaf.value]);
    expect([t.allowlist_node.label, hex(TAG_ALLOWLIST_NODE)]).toEqual([LABEL_ALLOWLIST_NODE, t.allowlist_node.value]);
    expect([t.action_binding.label, hex(TAG_ACTION_BINDING)]).toEqual([LABEL_ACTION_BINDING, t.action_binding.value]);
  });
});

describe('H', () => {
  it.each(vectors.poseidon2.map((v, i) => [i, v] as const))('poseidon2 vector %i', (_i, v) => {
    expect(hex(hasher.hash(v.inputs.map((x) => BigInt(x))))).toBe(v.hash);
  });

  it('spec 5.3 known answers', () => {
    expect(hex(hasher.hash([1000n]))).toBe('0x16433a80e26a23547e25d61dd95fd5793d1ca2dcd78ae64cd146d3b99a35fa7c');
    expect(hex(hasher.hash([1000n, 2000n]))).toBe('0x118d5a5ecb25dafe99eb45cb196604a23d0b7c0cbd0c2be29e0787e59b7a1d8a');
    expect(hex(hasher.hash([1000n, 2000n, 3000n]))).toBe('0x0f1badcd0d52ced816fb6e6826fdf66ada038135d53cbb993f320ca6529223cd');
  });

  it('refuses non-canonical inputs instead of reducing them', () => {
    expect(() => hasher.hash([FIELD_MODULUS])).toThrow(EncodingError);
    expect(() => hasher.hash([-1n])).toThrow(EncodingError);
    expect(() => hasher.hash([])).toThrow(EncodingError);
  });
});

describe('allowlist tree', () => {
  it('zero hashes', () => {
    expect(hasher.zeroHashes().map(hex)).toEqual(vectors.zero_hashes);
  });

  it('leaves', () => {
    expect(vectors.allowlist.recipients.map((r) => hex(hasher.leaf(BigInt(r))))).toEqual(vectors.allowlist.leaves);
  });

  it('root and every Merkle path, in insertion order as the fixture was built', () => {
    const tree = AllowlistTree.build(hasher, vectors.allowlist.recipients.map(BigInt), 'insertion');
    expect(hex(tree.root)).toBe(vectors.allowlist.root);
    for (const p of vectors.allowlist.proofs) {
      const w = tree.witness(BigInt(p.recipient))!;
      expect(String(w.leafIndex)).toBe(p.leaf_index);
      expect(w.path.map(hex)).toEqual(p.merkle_path);
      expect(hex(AllowlistTree.computeRoot(hasher, BigInt(p.leaf), w))).toBe(vectors.allowlist.root);
    }
    const w = tree.witness(BigInt(vectors.action.recipient))!;
    expect(String(w.leafIndex)).toBe(vectors.merkle_witness.leaf_index);
    expect(w.path.map(hex)).toEqual(vectors.merkle_witness.merkle_path);
  });

  it('empty allowlist has root Z[20]', () => {
    expect(hex(AllowlistTree.build(hasher, []).root)).toBe(vectors.zero_hashes[TREE_DEPTH]);
  });

  it('sorted placement depends only on the set', () => {
    const rs = vectors.allowlist.recipients.map(BigInt);
    const a = AllowlistTree.build(hasher, rs);
    const b = AllowlistTree.build(hasher, [...rs].reverse());
    expect(a.root).toBe(b.root);
    expect(a.recipients).toEqual([...rs].sort((x, y) => (x < y ? -1 : 1)));
    for (const r of rs) expect(AllowlistTree.computeRoot(hasher, hasher.leaf(r), a.witness(r)!)).toBe(a.root);
  });

  it('refuses duplicates and has no witness for an outsider', () => {
    const rs = vectors.allowlist.recipients.map(BigInt);
    expect(() => AllowlistTree.build(hasher, [rs[0]!, rs[0]!])).toThrow(/distinct/);
    expect(AllowlistTree.build(hasher, rs).witness(recipientId(SCENARIO.assetId, SCENARIO.outsider))).toBeUndefined();
  });
});

describe('policy commitment and action binding', () => {
  it('fixture policy commitment', () => {
    expect(hex(hasher.policyCommitment(policyFromJson(vectors.policy)))).toBe(vectors.policy_commitment);
  });

  it('fixture action binding', () => {
    expect(hex(hasher.actionBinding(actionFromJson(vectors.action)))).toBe(vectors.action_binding);
  });

  it.each(vectors.edge_cases.policy_commitments.map((v, i) => [i, v] as const))('edge-case commitment %i', (_i, v) => {
    expect(hex(hasher.policyCommitment(policyFromJson(v.policy)))).toBe(v.policy_commitment);
  });

  it.each(vectors.edge_cases.action_bindings.map((v, i) => [i, v] as const))('edge-case binding %i', (_i, v) => {
    expect(hex(hasher.actionBinding(actionFromJson(v.action)))).toBe(v.action_binding);
  });

  it('public inputs in order', () => {
    expect([vectors.policy_commitment, hex(BigInt(vectors.current_timestamp)), vectors.action_binding]).toEqual(vectors.public_inputs);
  });

  it('refuses out-of-range fields', () => {
    const p = policyFromJson(vectors.policy);
    expect(() => hasher.policyCommitment({ ...p, maxAmount: 1n << 128n })).toThrow(EncodingError);
    expect(() => hasher.policyCommitment({ ...p, expiry: 1n << 64n })).toThrow(EncodingError);
    expect(() => hasher.policyCommitment({ ...p, salt: FIELD_MODULUS })).toThrow(EncodingError);
    const a = actionFromJson(vectors.action);
    expect(() => hasher.actionBinding({ ...a, scopeIndex: 256 })).toThrow(EncodingError);
    expect(() => hasher.actionBinding({ ...a, scopeIndex: 1.5 })).toThrow(EncodingError);
    expect(() => hasher.actionBinding({ ...a, nonce: FIELD_MODULUS })).toThrow(EncodingError);
  });
});

describe('identifiers (spec 10.4)', () => {
  it('fixture tool_id, recipients, salt and nonce', () => {
    expect(hex(toolId(SCENARIO.serverId, SCENARIO.tool))).toBe(vectors.action.tool_id);
    expect(SCENARIO.accounts.map((a) => hex(recipientId(SCENARIO.assetId, a)))).toEqual(vectors.allowlist.recipients);
    expect(hex(toField('zkif.fixture.v1', 'policy-salt'))).toBe(vectors.policy.salt);
    expect(hex(toField('zkif.fixture.v1', 'nonce-0001'))).toBe(vectors.action.nonce);
  });

  it('testkit constants not exported to vectors.json', () => {
    // packages/zk-circuit/crates/testkit/src/scenario.nr
    expect(recipientId(SCENARIO.assetId, SCENARIO.outsider)).toBe(0xc7df553d4bf15854f17ad3e244ff85f79d212954d5e2909d407e8cb4dccb00n);
    expect(toolId(SCENARIO.serverId, 'refund_payment')).toBe(0x39aaafcb2d6728af8ab393a9c5d6a081a1f20a24b5bc32991210c8a9d6b0d5n);
    expect(toField('zkif.fixture.v1', 'nonce-0002')).toBe(0xfd7e42f0e6920839b40131b068608118c903e0b49134d27151897b0dc35f3an);
  });

  it('refuses parts containing a line feed', () => {
    expect(() => toolId('a\nb', 'c')).toThrow();
  });
});

describe('parsing', () => {
  it('fields', () => {
    expect(parseField('0x01')).toBe(1n);
    expect(() => parseField(vectors.constants.field_modulus)).toThrow(EncodingError);
    expect(() => parseField('123')).toThrow(EncodingError);
    expect(() => parseField(5)).toThrow(EncodingError);
  });

  it('integers', () => {
    expect(parseUint('340282366920938463463374607431768211455', 128)).toBe((1n << 128n) - 1n);
    expect(() => parseUint('340282366920938463463374607431768211456', 128)).toThrow(EncodingError);
    expect(parseUint(125, 128)).toBe(125n);
    expect(() => parseUint(2 ** 60, 128)).toThrow(EncodingError);
    expect(() => parseUint(1.5, 128)).toThrow(EncodingError);
    expect(() => parseUint('-1', 128)).toThrow(EncodingError);
    expect(() => parseUint('0x10', 128)).toThrow(EncodingError);
    expect(() => parseUint('007', 128)).toThrow(EncodingError);
  });
});
