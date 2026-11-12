//! C2: the recipient must be a leaf of the committed allowlist tree.

use super::helpers::{dense_witness, fixture, prove, single_witness};
use policy_primitives::constants::{MAX_LEAVES, TREE_DEPTH};
use testkit::scenario::{ALLOWLIST, OUTSIDER};

// --- recipient not in the allowlist ----------------------------------------------------------

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_recipient_outside_the_allowlist() {
    let mut s = fixture();
    // The path and position of a real member, reused for the outsider.
    s.action.recipient = OUTSIDER;
    s.action_binding = s.action.binding();
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_recipient_claimed_at_an_unoccupied_position() {
    let mut s = fixture();
    // Position 5 is the first empty one. Its path is valid for the empty leaf only.
    let (root, path) = dense_witness(ALLOWLIST, 5);
    assert_eq(root, s.policy.allowlist_root);
    s.action.recipient = OUTSIDER;
    s.leaf_index = 5;
    s.merkle_path = path;
    s.action_binding = s.action.binding();
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_recipient_that_is_only_in_another_tree() {
    let mut s = fixture();
    // A valid path, but to the root of a tree the policy never committed to.
    let (_, path) = single_witness(OUTSIDER, 0);
    s.action.recipient = OUTSIDER;
    s.leaf_index = 0;
    s.merkle_path = path;
    s.action_binding = s.action.binding();
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_the_zero_recipient() {
    let mut s = fixture();
    // Empty positions hold the value 0, but 0 as a recipient hashes to something else.
    let (_, path) = dense_witness(ALLOWLIST, 5);
    s.action.recipient = 0;
    s.leaf_index = 5;
    s.merkle_path = path;
    s.action_binding = s.action.binding();
    prove(s);
}

// --- wrong sibling ---------------------------------------------------------------------------

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_wrong_sibling_at_the_leaf_level() {
    let mut s = fixture();
    s.merkle_path[0] += 1;
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_wrong_sibling_in_the_middle_of_the_path() {
    let mut s = fixture();
    s.merkle_path[10] += 1;
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_wrong_sibling_just_below_the_root() {
    let mut s = fixture();
    s.merkle_path[TREE_DEPTH - 1] += 1;
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_two_siblings_in_swapped_order() {
    let mut s = fixture();
    let lowest = s.merkle_path[0];
    s.merkle_path[0] = s.merkle_path[1];
    s.merkle_path[1] = lowest;
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_the_path_of_another_member() {
    let mut s = fixture();
    let (_, path_of_position_1) = dense_witness(ALLOWLIST, 1);
    s.merkle_path = path_of_position_1;
    prove(s);
}

// --- wrong index bits ------------------------------------------------------------------------

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_flipped_lowest_index_bit() {
    let mut s = fixture();
    s.leaf_index = s.leaf_index ^ 1;
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_flipped_middle_index_bit() {
    let mut s = fixture();
    s.leaf_index = s.leaf_index ^ (1 << 10);
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_a_flipped_highest_index_bit() {
    let mut s = fixture();
    s.leaf_index = s.leaf_index ^ (1 << (TREE_DEPTH - 1));
    prove(s);
}

#[test(should_fail_with = "recipient not in allowlist")]
fn rejects_the_index_of_another_member() {
    let mut s = fixture();
    s.leaf_index = 0;
    prove(s);
}

// --- index range -----------------------------------------------------------------------------

#[test(should_fail_with = "leaf index out of range")]
fn rejects_a_leaf_index_equal_to_the_number_of_leaves() {
    let mut s = fixture();
    s.leaf_index = MAX_LEAVES;
    prove(s);
}

#[test(should_fail_with = "leaf index out of range")]
fn rejects_a_leaf_index_that_aliases_a_valid_one_in_its_low_bits() {
    let mut s = fixture();
    // The low 20 bits still say position 3.
    s.leaf_index = MAX_LEAVES + s.leaf_index;
    prove(s);
}

#[test(should_fail_with = "leaf index out of range")]
fn rejects_the_largest_u32_leaf_index() {
    let mut s = fixture();
    s.leaf_index = 0xffffffff;
    prove(s);
}
