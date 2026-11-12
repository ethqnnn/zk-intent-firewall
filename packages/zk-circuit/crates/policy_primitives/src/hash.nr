//! The protocol hash and the two Merkle hashes built on it.

use crate::constants::{TAG_ALLOWLIST_LEAF, TAG_ALLOWLIST_NODE};
use poseidon::poseidon2::Poseidon2;

/// The protocol hash `H`: the Poseidon2 sponge over BN254 (state width 4, rate 3, capacity 1) of
/// exactly `N` field elements.
///
/// The input length is part of the sponge's initial state, so inputs of different lengths cannot
/// collide. This is the only place where the external `poseidon` library is called. It is the same
/// function as `poseidon2Hash` in `@aztec/bb.js`.
pub fn poseidon2<let N: u32>(input: [Field; N]) -> Field {
    Poseidon2::hash(input, N)
}

/// Hash of an occupied allowlist leaf: `H(TAG_ALLOWLIST_LEAF, recipient)`.
pub fn hash_leaf(recipient: Field) -> Field {
    poseidon2([TAG_ALLOWLIST_LEAF, recipient])
}

/// Hash of an internal allowlist node: `H(TAG_ALLOWLIST_NODE, left, right)`.
///
/// It differs from `hash_leaf` in both tag and input length, so a node can never be presented as
/// a leaf.
pub fn hash_node(left: Field, right: Field) -> Field {
    poseidon2([TAG_ALLOWLIST_NODE, left, right])
}
