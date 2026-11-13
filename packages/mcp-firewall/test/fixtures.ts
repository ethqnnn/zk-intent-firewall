/** Typed access to packages/zk-circuit/fixtures. Read-only: the fixtures belong to Phase 1. */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const FIXTURES_DIR = fileURLToPath(new URL('../../zk-circuit/fixtures/', import.meta.url));

type Hex = string;
type Dec = string;
interface PolicyJson {
  max_amount: Dec;
  allowlist_root: Hex;
  scope_mask: Dec;
  expiry: Dec;
  salt: Hex;
}
interface ActionJson {
  tool_id: Hex;
  scope_index: Dec;
  amount: Dec;
  recipient: Hex;
  nonce: Hex;
}
export interface Vectors {
  constants: {
    field_modulus: Hex;
    largest_field_element: Hex;
    policy_version: Hex;
    tree_depth: Dec;
    max_leaves: Dec;
    scope_bits: Dec;
    empty_leaf: Hex;
    domain_tags: Record<'policy_commitment' | 'allowlist_leaf' | 'allowlist_node' | 'action_binding', { label: string; value: Hex }>;
  };
  poseidon2: { inputs: Hex[]; hash: Hex }[];
  zero_hashes: Hex[];
  allowlist: {
    recipients: Hex[];
    leaves: Hex[];
    root: Hex;
    proofs: { leaf_index: Dec; recipient: Hex; leaf: Hex; merkle_path: Hex[] }[];
  };
  policy: PolicyJson;
  policy_commitment: Hex;
  action: ActionJson;
  action_binding: Hex;
  current_timestamp: Dec;
  merkle_witness: { leaf_index: Dec; merkle_path: Hex[] };
  public_inputs: [Hex, Hex, Hex];
  edge_cases: {
    policy_commitments: { policy: PolicyJson; policy_commitment: Hex }[];
    action_bindings: { action: ActionJson; action_binding: Hex }[];
  };
}

export const vectors: Vectors = JSON.parse(readFileSync(FIXTURES_DIR + 'vectors.json', 'utf8'));

export const vkHashes: Record<string, string> = Object.fromEntries(
  readFileSync(FIXTURES_DIR + 'vk_hashes.txt', 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '' && !l.startsWith('#'))
    .map((l) => l.trim().split(/\s+/) as [string, string]),
);

export const policyFromJson = (p: PolicyJson) => ({
  maxAmount: BigInt(p.max_amount),
  allowlistRoot: BigInt(p.allowlist_root),
  scopeMask: BigInt(p.scope_mask),
  expiry: BigInt(p.expiry),
  salt: BigInt(p.salt),
});

export const actionFromJson = (a: ActionJson) => ({
  toolId: BigInt(a.tool_id),
  scopeIndex: Number(a.scope_index),
  amount: BigInt(a.amount),
  recipient: BigInt(a.recipient),
  nonce: BigInt(a.nonce),
});

/** The fixture scenario in human terms (docs/circuit-spec.md, section 10.6). */
export const SCENARIO = {
  serverId: 'https://payments.example.com/mcp',
  tool: 'send_payment',
  assetId: 'eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
  /** `eip155:1:0x` followed by forty times the digit d, for d = 1 ... 5. Position k holds d = k + 1. */
  accounts: [1, 2, 3, 4, 5].map((d) => 'eip155:1:0x' + String(d).repeat(40)),
  /** Same derivation with the digit 9: not on the allowlist. */
  outsider: 'eip155:1:0x' + '9'.repeat(40),
  maxAmount: 500_000_000n,
  amount: 125_000_000n,
  scopes: [0, 3, 17],
  scopeIndex: 3,
  expiry: 1798761600n,
  now: 1794441600n,
  leafIndex: 3,
};
