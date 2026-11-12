//! Merkle root recomputation for the recipient allowlist tree.

use crate::constants::TREE_DEPTH;
use crate::hash::hash_node;

/// Recomputes the root of the allowlist tree from a leaf value, its position and its sibling path.
///
/// `path[h]` is the sibling of the path node at height `h`, starting at the leaf level. Bit `h` of
/// `leaf_index`, least significant first, says on which side the path node sits at height `h`:
/// 0 for a left child, 1 for a right child.
///
/// The direction bits come from `Field::to_le_bits`, which constrains each bit to be boolean and
/// the bits to recompose to `leaf_index`. A `leaf_index` of `2^TREE_DEPTH` or more therefore has
/// no valid decomposition and makes the circuit unsatisfiable.
pub fn compute_root(leaf: Field, leaf_index: u32, path: [Field; TREE_DEPTH]) -> Field {
    let is_right_child: [bool; TREE_DEPTH] = (leaf_index as Field).to_le_bits();
    let mut node = leaf;
    for height in 0..TREE_DEPTH {
        let sibling = path[height];
        let (left, right) = if is_right_child[height] {
            (sibling, node)
        } else {
            (node, sibling)
        };
        node = hash_node(left, right);
    }
    node
}
