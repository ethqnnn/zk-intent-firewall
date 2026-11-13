/**
 * Protocol constants (docs/circuit-spec.md, section 5.4). They must equal the circuit's
 * `policy_primitives::constants`; test/vectors.test.ts checks them against fixtures/vectors.json.
 */

/**
 * A domain tag: the ASCII label read as a big-endian integer. Labels are at most 31 bytes, so a
 * tag is always a canonical field element.
 */
export function tagFromLabel(label: string): bigint {
  if (!/^[\x20-\x7e]{1,31}$/.test(label)) throw new Error('a tag label is 1 to 31 printable ASCII characters');
  return BigInt('0x' + Buffer.from(label, 'ascii').toString('hex'));
}

export const LABEL_POLICY_COMMITMENT = 'zkif.policy.commitment.v1';
export const LABEL_ALLOWLIST_LEAF = 'zkif.allowlist.leaf.v1';
export const LABEL_ALLOWLIST_NODE = 'zkif.allowlist.node.v1';
export const LABEL_ACTION_BINDING = 'zkif.action.binding.v1';

export const TAG_POLICY_COMMITMENT = tagFromLabel(LABEL_POLICY_COMMITMENT);
export const TAG_ALLOWLIST_LEAF = tagFromLabel(LABEL_ALLOWLIST_LEAF);
export const TAG_ALLOWLIST_NODE = tagFromLabel(LABEL_ALLOWLIST_NODE);
export const TAG_ACTION_BINDING = tagFromLabel(LABEL_ACTION_BINDING);

/** Version of the policy schema, hashed into every commitment. */
export const POLICY_VERSION = 1n;
/** Levels between a leaf and the root of the allowlist tree. */
export const TREE_DEPTH = 20;
/** `2^TREE_DEPTH`. */
export const MAX_LEAVES = 1 << TREE_DEPTH;
/** Width of `scope_mask`. */
export const SCOPE_BITS = 64;
/** Value of an unoccupied leaf position. */
export const EMPTY_LEAF = 0n;
