//! Protocol constants. Changing any of them changes the circuit and its verification key.

/// Number of levels between a leaf of the recipient allowlist tree and its root.
pub global TREE_DEPTH: u32 = 20;

/// Number of leaf positions in the allowlist tree: `2^TREE_DEPTH`.
pub global MAX_LEAVES: u32 = 1 << TREE_DEPTH;

/// Width of `Policy::scope_mask` in bits. Valid scope indices are `0..SCOPE_BITS`.
pub global SCOPE_BITS: u32 = 64;

/// Version of the policy schema. It is hashed into every policy commitment, so a commitment made
/// for one schema can never be opened under another.
pub global POLICY_VERSION: Field = 1;

/// Value of an unoccupied leaf position. It is the field element zero, not a hash, so no recipient
/// can ever open it.
pub global EMPTY_LEAF: Field = 0;

// Domain separation tags. Each tag is its ASCII label read as a big-endian integer. The test
// `domain_tags_encode_their_ascii_labels` recomputes every value from its label.

/// ASCII `zkif.policy.commitment.v1`.
pub global TAG_POLICY_COMMITMENT: Field = 0x7a6b69662e706f6c6963792e636f6d6d69746d656e742e7631;

/// ASCII `zkif.allowlist.leaf.v1`.
pub global TAG_ALLOWLIST_LEAF: Field = 0x7a6b69662e616c6c6f776c6973742e6c6561662e7631;

/// ASCII `zkif.allowlist.node.v1`.
pub global TAG_ALLOWLIST_NODE: Field = 0x7a6b69662e616c6c6f776c6973742e6e6f64652e7631;

/// ASCII `zkif.action.binding.v1`.
pub global TAG_ACTION_BINDING: Field = 0x7a6b69662e616374696f6e2e62696e64696e672e7631;
