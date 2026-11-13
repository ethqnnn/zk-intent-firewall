//! Reference implementation of the recipient allowlist tree (`docs/circuit-spec.md`, section 5.6).
//!
//! Phase 2 builds the same tree in TypeScript. This is the behaviour it must reproduce.

use policy_primitives::constants::{EMPTY_LEAF, MAX_LEAVES, TREE_DEPTH};
use policy_primitives::hash::{hash_leaf, hash_node};

/// `Z[h]`, the value of an empty subtree of height `h`:
/// `Z[0] = EMPTY_LEAF` and `Z[h + 1] = hash_node(Z[h], Z[h])`.
///
/// `Z[TREE_DEPTH]` is the root of an empty allowlist.
pub unconstrained fn zero_hashes() -> [Field; TREE_DEPTH + 1] {
    let mut zeros = [EMPTY_LEAF; TREE_DEPTH + 1];
    for height in 0..TREE_DEPTH {
        zeros[height + 1] = hash_node(zeros[height], zeros[height]);
    }
    zeros
}

/// Builds the tree that holds `leaves[k]` at position `positions[k]` and `EMPTY_LEAF` everywhere
/// else. Returns its root and the Merkle path of position `target`.
///
/// `positions` must be strictly ascending. `target` does not have to be occupied. Only the nodes
/// above an occupied leaf are hashed, so the cost is `N * TREE_DEPTH` hashes at most.
pub unconstrained fn root_and_path<let N: u32>(
    positions: [u32; N],
    leaves: [Field; N],
    target: u32,
) -> (Field, [Field; TREE_DEPTH]) {
    assert(N != 0, "use zero_hashes()[TREE_DEPTH] for the root of an empty tree");
    assert(target < MAX_LEAVES, "target position out of range");
    for k in 0..N {
        assert(positions[k] < MAX_LEAVES, "leaf position out of range");
        if k != 0 {
            assert(positions[k - 1] < positions[k], "positions must be strictly ascending");
        }
    }

    let zeros = zero_hashes();
    // The non-empty nodes at the current height, in ascending order of position.
    let mut node_position = positions;
    let mut node_value = leaves;
    let mut count = N;
    let mut cursor = target;
    let mut path = [0; TREE_DEPTH];

    for height in 0..TREE_DEPTH {
        // The sibling of the path node is its neighbour, or an empty subtree.
        let sibling_position = cursor ^ 1;
        let mut sibling = zeros[height];
        for k in 0..count {
            if node_position[k] == sibling_position {
                sibling = node_value[k];
            }
        }
        path[height] = sibling;

        // Hash every pair that has at least one non-empty child into its parent.
        let mut parent_position = [0; N];
        let mut parent_value = [0; N];
        let mut parent_count = 0;
        let mut k = 0;
        while k < count {
            let mut left = zeros[height];
            let mut right = zeros[height];
            if node_position[k] % 2 == 0 {
                left = node_value[k];
                if k + 1 < count {
                    if node_position[k + 1] == node_position[k] + 1 {
                        right = node_value[k + 1];
                        k += 1;
                    }
                }
            } else {
                right = node_value[k];
            }
            parent_position[parent_count] = node_position[k] / 2;
            parent_value[parent_count] = hash_node(left, right);
            parent_count += 1;
            k += 1;
        }

        node_position = parent_position;
        node_value = parent_value;
        count = parent_count;
        cursor = cursor / 2;
    }

    (node_value[0], path)
}

/// The allowlist that holds `recipients[k]` at position `k`. Returns its root and the Merkle path
/// of position `target`.
pub unconstrained fn dense_allowlist<let N: u32>(
    recipients: [Field; N],
    target: u32,
) -> (Field, [Field; TREE_DEPTH]) {
    let mut positions = [0; N];
    let mut leaves = [0; N];
    for k in 0..N {
        positions[k] = k;
        leaves[k] = hash_leaf(recipients[k]);
    }
    root_and_path(positions, leaves, target)
}

/// The allowlist that holds one recipient, at `position`. Returns its root and the Merkle path of
/// that position.
pub unconstrained fn single_recipient_allowlist(
    recipient: Field,
    position: u32,
) -> (Field, [Field; TREE_DEPTH]) {
    root_and_path([position], [hash_leaf(recipient)], position)
}
