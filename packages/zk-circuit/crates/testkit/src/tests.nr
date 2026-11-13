//! Tests of the reference tree builder against the circuit's own Merkle code.
//!
//! The test functions are constrained, so `compute_root` runs here exactly as it does in the
//! circuit. Only the tree builder runs unconstrained.

use crate::scenario::{
    ALLOWLIST, AMOUNT, canonical, EXPIRY, LEAF_INDEX, MAX_AMOUNT, NONCE, NOW, OUTSIDER, POLICY_SALT,
    SCOPE_INDEX, SCOPE_MASK, TOOL_SEND_PAYMENT,
};
use crate::tree::{dense_allowlist, root_and_path, single_recipient_allowlist, zero_hashes};
use policy_primitives::constants::{EMPTY_LEAF, MAX_LEAVES, TREE_DEPTH};
use policy_primitives::hash::{hash_leaf, hash_node};
use policy_primitives::merkle::compute_root;

fn zeros() -> [Field; TREE_DEPTH + 1] {
    // Safety: test inputs only. The assertions below recompute what they check.
    unsafe {
        zero_hashes()
    }
}

fn dense<let N: u32>(recipients: [Field; N], target: u32) -> (Field, [Field; TREE_DEPTH]) {
    // Safety: test inputs only. The assertions below recompute what they check.
    unsafe {
        dense_allowlist(recipients, target)
    }
}

fn sparse<let N: u32>(
    positions: [u32; N],
    leaves: [Field; N],
    target: u32,
) -> (Field, [Field; TREE_DEPTH]) {
    // Safety: test inputs only. The assertions below recompute what they check.
    unsafe {
        root_and_path(positions, leaves, target)
    }
}

#[test]
fn zero_hashes_follow_their_definition() {
    let z = zeros();
    assert_eq(z[0], EMPTY_LEAF);
    for height in 0..TREE_DEPTH {
        assert_eq(z[height + 1], hash_node(z[height], z[height]));
    }
}

#[test]
fn empty_tree_root_opens_to_the_empty_leaf_at_any_position() {
    let z = zeros();
    let mut path = [0; TREE_DEPTH];
    for height in 0..TREE_DEPTH {
        path[height] = z[height];
    }
    let positions: [u32; 4] = [0, 1, 524288, MAX_LEAVES - 1];
    for k in 0..4 {
        assert_eq(compute_root(EMPTY_LEAF, positions[k], path), z[TREE_DEPTH]);
    }
}

#[test]
fn dense_allowlist_root_matches_a_tree_built_by_hand() {
    let z = zeros();
    let leaf = ALLOWLIST.map(|recipient| hash_leaf(recipient));

    // Height 1: positions 0 to 7 pair up as (0,1) (2,3) (4,empty) (empty,empty).
    let n01 = hash_node(leaf[0], leaf[1]);
    let n23 = hash_node(leaf[2], leaf[3]);
    let n45 = hash_node(leaf[4], EMPTY_LEAF);
    // Height 2.
    let n0123 = hash_node(n01, n23);
    let n4567 = hash_node(n45, z[1]);
    // Height 3, then an empty subtree on the right all the way up.
    let mut root = hash_node(n0123, n4567);
    for height in 3..TREE_DEPTH {
        root = hash_node(root, z[height]);
    }

    let (built_root, _) = dense(ALLOWLIST, 0);
    assert_eq(built_root, root);
}

#[test]
fn every_allowlisted_recipient_has_a_path_to_the_same_root() {
    let (root, _) = dense(ALLOWLIST, 0);
    for k in 0..5 {
        let (root_k, path) = dense(ALLOWLIST, k);
        assert_eq(root_k, root);
        assert_eq(compute_root(hash_leaf(ALLOWLIST[k]), k, path), root);
    }
}

#[test]
fn path_of_the_fixture_recipient_is_built_from_the_expected_siblings() {
    let z = zeros();
    let leaf = ALLOWLIST.map(|recipient| hash_leaf(recipient));
    let (_, path) = dense(ALLOWLIST, 3);

    // Position 3: sibling leaf 2, then the node over leaves 0 and 1, then the node over leaves
    // 4 to 7, then empty subtrees.
    assert_eq(path[0], leaf[2]);
    assert_eq(path[1], hash_node(leaf[0], leaf[1]));
    assert_eq(path[2], hash_node(hash_node(leaf[4], EMPTY_LEAF), z[1]));
    for height in 3..TREE_DEPTH {
        assert_eq(path[height], z[height]);
    }
}

#[test]
fn path_of_an_unoccupied_position_opens_to_the_empty_leaf() {
    let (root, _) = dense(ALLOWLIST, 0);
    let positions: [u32; 3] = [5, 777777, MAX_LEAVES - 1];
    for k in 0..3 {
        let (root_k, path) = dense(ALLOWLIST, positions[k]);
        assert_eq(root_k, root);
        assert_eq(compute_root(EMPTY_LEAF, positions[k], path), root);
        // The outsider cannot be opened there.
        assert(compute_root(hash_leaf(OUTSIDER), positions[k], path) != root);
    }
}

#[test]
fn single_recipient_at_the_last_position_sits_on_the_right_at_every_height() {
    let z = zeros();
    let last = MAX_LEAVES - 1;
    // Safety: test inputs only. The assertions below recompute what they check.
    let (root, path) = unsafe { single_recipient_allowlist(OUTSIDER, last) };

    let mut expected = hash_leaf(OUTSIDER);
    for height in 0..TREE_DEPTH {
        assert_eq(path[height], z[height]);
        expected = hash_node(z[height], expected);
    }
    assert_eq(root, expected);
    assert_eq(compute_root(hash_leaf(OUTSIDER), last, path), root);
}

#[test]
fn sparse_positions_share_one_root_and_each_has_a_valid_path() {
    let positions: [u32; 4] = [0, 5, 524288, MAX_LEAVES - 1];
    let leaves: [Field; 4] = [hash_leaf(11), hash_leaf(22), hash_leaf(33), hash_leaf(44)];
    let (root, _) = sparse(positions, leaves, 0);
    for k in 0..4 {
        let (root_k, path) = sparse(positions, leaves, positions[k]);
        assert_eq(root_k, root);
        assert_eq(compute_root(leaves[k], positions[k], path), root);
    }
    // A leaf opened at another leaf's position does not verify.
    let (_, path_of_first) = sparse(positions, leaves, 0);
    assert(compute_root(leaves[1], 0, path_of_first) != root);
}

#[test]
fn root_depends_on_the_position_of_a_recipient() {
    let leaf = hash_leaf(11);
    let (root_at_0, _) = sparse([0], [leaf], 0);
    let (root_at_1, _) = sparse([1], [leaf], 1);
    assert(root_at_0 != root_at_1);
}

#[test(should_fail_with = "positions must be strictly ascending")]
fn tree_builder_rejects_unsorted_positions() {
    let _ = sparse([5, 2], [hash_leaf(1), hash_leaf(2)], 2);
}

#[test(should_fail_with = "positions must be strictly ascending")]
fn tree_builder_rejects_duplicate_positions() {
    let _ = sparse([2, 2], [hash_leaf(1), hash_leaf(2)], 2);
}

#[test(should_fail_with = "leaf position out of range")]
fn tree_builder_rejects_a_position_beyond_the_tree() {
    let _ = sparse([MAX_LEAVES], [hash_leaf(1)], 0);
}

#[test(should_fail_with = "target position out of range")]
fn tree_builder_rejects_a_target_beyond_the_tree() {
    let _ = sparse([0], [hash_leaf(1)], MAX_LEAVES);
}

#[test]
fn canonical_scenario_is_self_consistent() {
    // Safety: test inputs only. The assertions below recompute what they check.
    let s = unsafe { canonical() };

    assert_eq(s.policy.max_amount, MAX_AMOUNT);
    assert_eq(s.policy.scope_mask, SCOPE_MASK);
    assert_eq(s.policy.expiry, EXPIRY);
    assert_eq(s.policy.salt, POLICY_SALT);
    assert_eq(s.action.tool_id, TOOL_SEND_PAYMENT);
    assert_eq(s.action.scope_index, SCOPE_INDEX);
    assert_eq(s.action.amount, AMOUNT);
    assert_eq(s.action.recipient, ALLOWLIST[LEAF_INDEX]);
    assert_eq(s.action.nonce, NONCE);
    assert_eq(s.current_timestamp, NOW);
    assert_eq(s.leaf_index, LEAF_INDEX);

    assert_eq(s.policy_commitment, s.policy.commitment());
    assert_eq(s.action_binding, s.action.binding());
    assert_eq(
        compute_root(hash_leaf(s.action.recipient), s.leaf_index, s.merkle_path),
        s.policy.allowlist_root,
    );
}

#[test]
fn canonical_scenario_constants_mean_what_their_comments_say() {
    // Scopes 0, 3 and 17.
    assert_eq(SCOPE_MASK, (1 << 0) | (1 << 3) | (1 << 17));
    assert(AMOUNT <= MAX_AMOUNT);
    assert(NOW < EXPIRY);
    // No two recipients are equal, and the outsider is none of them.
    for i in 0..5 {
        assert(ALLOWLIST[i] != OUTSIDER);
        for j in 0..5 {
            if i != j {
                assert(ALLOWLIST[i] != ALLOWLIST[j]);
            }
        }
    }
}
