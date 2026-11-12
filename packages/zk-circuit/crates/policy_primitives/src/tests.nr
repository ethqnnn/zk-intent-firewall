//! Unit tests for the primitives.
//!
//! Inputs go through `black_box` where the code under test would otherwise be folded away at
//! compile time, so that the constrained code actually runs on witnesses.

use crate::action::Action;
use crate::constants::{
    EMPTY_LEAF, MAX_LEAVES, POLICY_VERSION, SCOPE_BITS, TAG_ACTION_BINDING, TAG_ALLOWLIST_LEAF,
    TAG_ALLOWLIST_NODE, TAG_POLICY_COMMITMENT, TREE_DEPTH,
};
use crate::hash::{hash_leaf, hash_node, poseidon2};
use crate::merkle::compute_root;
use crate::policy::Policy;
use std::hint::black_box;

global U64_MAX: u64 = 0xffffffffffffffff;
global U128_MAX: u128 = 0xffffffffffffffffffffffffffffffff;

// ---------------------------------------------------------------------------------------------
// Field and constants
// ---------------------------------------------------------------------------------------------

#[test]
fn field_is_the_bn254_scalar_field() {
    let p_minus_one: Field = 0 - 1;
    assert_eq(p_minus_one, 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000);
}

#[test]
fn protocol_constants_have_their_specified_values() {
    assert_eq(TREE_DEPTH, 20);
    assert_eq(MAX_LEAVES, 1048576);
    assert_eq(SCOPE_BITS, 64);
    assert_eq(POLICY_VERSION, 1);
    assert_eq(EMPTY_LEAF, 0);
}

/// The ASCII bytes of `label` read as a big-endian integer.
fn tag_of<let N: u32>(label: str<N>) -> Field {
    let bytes = label.as_bytes();
    let mut value: Field = 0;
    for i in 0..N {
        value = value * 256 + bytes[i] as Field;
    }
    value
}

#[test]
fn domain_tags_encode_their_ascii_labels() {
    assert_eq(TAG_POLICY_COMMITMENT, tag_of("zkif.policy.commitment.v1"));
    assert_eq(TAG_ALLOWLIST_LEAF, tag_of("zkif.allowlist.leaf.v1"));
    assert_eq(TAG_ALLOWLIST_NODE, tag_of("zkif.allowlist.node.v1"));
    assert_eq(TAG_ACTION_BINDING, tag_of("zkif.action.binding.v1"));
}

#[test]
fn domain_tags_are_pairwise_distinct() {
    let tags = [TAG_POLICY_COMMITMENT, TAG_ALLOWLIST_LEAF, TAG_ALLOWLIST_NODE, TAG_ACTION_BINDING];
    for i in 0..4 {
        for j in 0..4 {
            if i != j {
                assert(tags[i] != tags[j]);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Poseidon2
// ---------------------------------------------------------------------------------------------

#[test]
fn poseidon2_permutation_matches_the_stdlib_known_answer() {
    let state = std::hash::poseidon2_permutation(black_box([0, 1, 2, 3]));
    assert_eq(state[0], 0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737);
}

// Vectors from the test suite of noir-lang/poseidon, which checks them against @aztec/bb.js.
#[test]
fn poseidon2_matches_upstream_known_answers() {
    assert_eq(
        poseidon2(black_box([1000])),
        0x16433a80e26a23547e25d61dd95fd5793d1ca2dcd78ae64cd146d3b99a35fa7c,
    );
    assert_eq(
        poseidon2(black_box([1000, 2000])),
        0x118d5a5ecb25dafe99eb45cb196604a23d0b7c0cbd0c2be29e0787e59b7a1d8a,
    );
    assert_eq(
        poseidon2(black_box([1000, 2000, 3000])),
        0x0f1badcd0d52ced816fb6e6826fdf66ada038135d53cbb993f320ca6529223cd,
    );
}

// The same vectors through the branch the upstream sponge takes in unconstrained code, which is
// the branch `testkit` and `fixture_gen` run.
#[test]
unconstrained fn poseidon2_matches_upstream_known_answers_when_unconstrained() {
    assert_eq(
        poseidon2(black_box([1000])),
        0x16433a80e26a23547e25d61dd95fd5793d1ca2dcd78ae64cd146d3b99a35fa7c,
    );
    assert_eq(
        poseidon2(black_box([1000, 2000])),
        0x118d5a5ecb25dafe99eb45cb196604a23d0b7c0cbd0c2be29e0787e59b7a1d8a,
    );
    assert_eq(
        poseidon2(black_box([1000, 2000, 3000])),
        0x0f1badcd0d52ced816fb6e6826fdf66ada038135d53cbb993f320ca6529223cd,
    );
}

/// The sponge of `docs/circuit-spec.md`, section 5.3, written out for the four input lengths the
/// protocol uses.
fn sponge_by_hand_2(x: [Field; 2]) -> Field {
    std::hash::poseidon2_permutation([x[0], x[1], 0, 2 * 18446744073709551616])[0]
}

fn sponge_by_hand_3(x: [Field; 3]) -> Field {
    std::hash::poseidon2_permutation([x[0], x[1], x[2], 3 * 18446744073709551616])[0]
}

fn sponge_by_hand_6(x: [Field; 6]) -> Field {
    let s = std::hash::poseidon2_permutation([x[0], x[1], x[2], 6 * 18446744073709551616]);
    std::hash::poseidon2_permutation([s[0] + x[3], s[1] + x[4], s[2] + x[5], s[3]])[0]
}

fn sponge_by_hand_7(x: [Field; 7]) -> Field {
    let s = std::hash::poseidon2_permutation([x[0], x[1], x[2], 7 * 18446744073709551616]);
    let s = std::hash::poseidon2_permutation([s[0] + x[3], s[1] + x[4], s[2] + x[5], s[3]]);
    std::hash::poseidon2_permutation([s[0] + x[6], s[1], s[2], s[3]])[0]
}

#[test]
fn poseidon2_is_the_specified_sponge() {
    let x: [Field; 7] = black_box([11, 22, 33, 44, 55, 66, 0 - 1]);
    assert_eq(poseidon2([x[0], x[1]]), sponge_by_hand_2([x[0], x[1]]));
    assert_eq(poseidon2([x[0], x[1], x[2]]), sponge_by_hand_3([x[0], x[1], x[2]]));
    assert_eq(
        poseidon2([x[0], x[1], x[2], x[3], x[4], x[5]]),
        sponge_by_hand_6([x[0], x[1], x[2], x[3], x[4], x[5]]),
    );
    assert_eq(poseidon2(x), sponge_by_hand_7(x));
}

#[test]
fn poseidon2_separates_input_lengths() {
    let x: [Field; 2] = black_box([5, 6]);
    assert(poseidon2([x[0], x[1]]) != poseidon2([x[0], x[1], 0]));
    assert(poseidon2([x[0], x[1], 0]) != poseidon2([x[0], x[1], 0, 0]));
    assert(poseidon2([x[0]]) != poseidon2([x[0], 0]));
}

// ---------------------------------------------------------------------------------------------
// Merkle hashes
// ---------------------------------------------------------------------------------------------

#[test]
fn leaf_hash_follows_its_definition() {
    let recipient: Field = black_box(42);
    assert_eq(hash_leaf(recipient), poseidon2([TAG_ALLOWLIST_LEAF, recipient]));
}

#[test]
fn node_hash_follows_its_definition() {
    let children: [Field; 2] = black_box([42, 43]);
    assert_eq(
        hash_node(children[0], children[1]),
        poseidon2([TAG_ALLOWLIST_NODE, children[0], children[1]]),
    );
}

#[test]
fn leaf_and_node_hashes_are_domain_separated() {
    let x: Field = black_box(7);
    // Same payload, the two real hashes.
    assert(hash_leaf(x) != hash_node(x, 0));
    // Same length, different tag.
    assert(poseidon2([TAG_ALLOWLIST_LEAF, x, 0]) != hash_node(x, 0));
    assert(poseidon2([TAG_ALLOWLIST_NODE, x]) != hash_leaf(x));
    // A leaf hash fed back in as a recipient is not a node, and the other way round.
    assert(hash_leaf(hash_node(x, x)) != hash_node(x, x));
    assert(hash_node(hash_leaf(x), hash_leaf(x)) != hash_leaf(x));
}

#[test]
fn node_hash_depends_on_child_order() {
    let children: [Field; 2] = black_box([1, 2]);
    assert(hash_node(children[0], children[1]) != hash_node(children[1], children[0]));
}

// ---------------------------------------------------------------------------------------------
// Merkle root
// ---------------------------------------------------------------------------------------------

fn sample_path() -> [Field; TREE_DEPTH] {
    let mut path = [0; TREE_DEPTH];
    for height in 0..TREE_DEPTH {
        path[height] = (1000 + height) as Field;
    }
    black_box(path)
}

#[test]
fn compute_root_at_the_first_position_keeps_the_node_on_the_left() {
    let leaf = hash_leaf(black_box(5));
    let path = sample_path();
    let mut expected = leaf;
    for height in 0..TREE_DEPTH {
        expected = hash_node(expected, path[height]);
    }
    assert_eq(compute_root(leaf, black_box(0), path), expected);
}

#[test]
fn compute_root_at_the_last_position_keeps_the_node_on_the_right() {
    let leaf = hash_leaf(black_box(5));
    let path = sample_path();
    let mut expected = leaf;
    for height in 0..TREE_DEPTH {
        expected = hash_node(path[height], expected);
    }
    assert_eq(compute_root(leaf, black_box(MAX_LEAVES - 1), path), expected);
}

#[test]
fn compute_root_reads_index_bits_least_significant_first() {
    let leaf = hash_leaf(black_box(5));
    let path = sample_path();
    // Position 6 is binary 110: left child at height 0, right child at heights 1 and 2, and a left
    // child from there up.
    let mut expected = hash_node(leaf, path[0]);
    expected = hash_node(path[1], expected);
    expected = hash_node(path[2], expected);
    for height in 3..TREE_DEPTH {
        expected = hash_node(expected, path[height]);
    }
    assert_eq(compute_root(leaf, black_box(6), path), expected);
}

#[test]
fn compute_root_changes_with_every_index_bit() {
    let leaf = hash_leaf(black_box(5));
    let path = sample_path();
    let base = compute_root(leaf, black_box(0), path);
    for bit in 0..TREE_DEPTH {
        let index: u32 = black_box(1 << bit);
        assert(compute_root(leaf, index, path) != base);
    }
}

#[test]
fn compute_root_changes_with_every_sibling() {
    let leaf = hash_leaf(black_box(5));
    let path = sample_path();
    let index: u32 = black_box(699050); // binary 10101010101010101010
    let base = compute_root(leaf, index, path);
    for height in 0..TREE_DEPTH {
        let mut tampered = path;
        tampered[height] += 1;
        assert(compute_root(leaf, index, tampered) != base);
    }
}

#[test]
fn compute_root_changes_with_the_leaf() {
    let path = sample_path();
    let index: u32 = black_box(3);
    let recipients: [Field; 2] = black_box([5, 6]);
    assert(
        compute_root(hash_leaf(recipients[0]), index, path)
            != compute_root(hash_leaf(recipients[1]), index, path),
    );
}

#[test(should_fail_with = "Field failed to decompose into specified 20 limbs")]
fn compute_root_has_no_solution_for_an_index_beyond_the_tree() {
    let leaf = hash_leaf(black_box(5));
    let _ = compute_root(leaf, black_box(MAX_LEAVES), sample_path());
}

// ---------------------------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------------------------

fn sample_policy() -> Policy {
    black_box(
        Policy {
            max_amount: 500_000_000,
            allowlist_root: 0x1234,
            scope_mask: 131081,
            expiry: 1798761600,
            salt: 0xabcdef,
        },
    )
}

#[test]
fn commitment_follows_its_definition() {
    let policy = sample_policy();
    assert_eq(
        policy.commitment(),
        poseidon2([
            TAG_POLICY_COMMITMENT,
            POLICY_VERSION,
            500_000_000,
            0x1234,
            131081,
            1798761600,
            0xabcdef,
        ]),
    );
}

#[test]
fn commitment_keeps_the_full_width_of_every_integer() {
    let policy = black_box(
        Policy {
            max_amount: U128_MAX,
            allowlist_root: 0 - 1,
            scope_mask: U64_MAX,
            expiry: U64_MAX,
            salt: 0 - 1,
        },
    );
    assert_eq(
        policy.commitment(),
        poseidon2([
            TAG_POLICY_COMMITMENT,
            POLICY_VERSION,
            0xffffffffffffffffffffffffffffffff,
            0 - 1,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0 - 1,
        ]),
    );
}

#[test]
fn commitment_changes_with_every_field() {
    let base = sample_policy();
    let commitment = base.commitment();

    let mut changed = base;
    changed.max_amount += 1;
    assert(changed.commitment() != commitment);

    let mut changed = base;
    changed.allowlist_root += 1;
    assert(changed.commitment() != commitment);

    let mut changed = base;
    changed.scope_mask += 1;
    assert(changed.commitment() != commitment);

    let mut changed = base;
    changed.expiry += 1;
    assert(changed.commitment() != commitment);

    let mut changed = base;
    changed.salt += 1;
    assert(changed.commitment() != commitment);
}

#[test]
fn commitment_does_not_confuse_fields_of_the_same_type() {
    let base = sample_policy();
    let mut swapped = base;
    swapped.scope_mask = base.expiry;
    swapped.expiry = base.scope_mask;
    assert(swapped.commitment() != base.commitment());

    let mut swapped = base;
    swapped.allowlist_root = base.salt;
    swapped.salt = base.allowlist_root;
    assert(swapped.commitment() != base.commitment());
}

#[test]
fn grants_scope_reads_exactly_the_indexed_bit() {
    for bit in 0..SCOPE_BITS {
        let policy = black_box(
            Policy {
                max_amount: 1,
                allowlist_root: 0,
                scope_mask: 1 << (bit as u64),
                expiry: 1,
                salt: 1,
            },
        );
        let index: u8 = black_box(bit as u8);
        assert(policy.grants_scope(index));
        if bit != 0 {
            assert(!policy.grants_scope(index - 1));
        }
        if bit != SCOPE_BITS - 1 {
            assert(!policy.grants_scope(index + 1));
        }
    }
}

#[test]
fn grants_scope_agrees_with_shifting_for_mixed_masks() {
    // Alternating bits, the fixture mask, every bit and no bit.
    let masks: [u64; 5] = [0xaaaaaaaaaaaaaaaa, 0x5555555555555555, 131081, U64_MAX, 0];
    for m in 0..5 {
        let policy = black_box(
            Policy { max_amount: 1, allowlist_root: 0, scope_mask: masks[m], expiry: 1, salt: 1 },
        );
        for bit in 0..SCOPE_BITS {
            let expected = ((masks[m] >> (bit as u64)) & 1) == 1;
            assert_eq(policy.grants_scope(black_box(bit as u8)), expected);
        }
    }
}

#[test]
fn grants_scope_denies_every_index_beyond_the_mask() {
    // Every bit is granted, so only the index can make the answer no.
    let policy = black_box(
        Policy { max_amount: 1, allowlist_root: 0, scope_mask: U64_MAX, expiry: 1, salt: 1 },
    );
    assert(policy.grants_scope(black_box(63)));
    for index in 64..256 {
        assert(!policy.grants_scope(black_box(index as u8)));
    }
}

// ---------------------------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------------------------

fn sample_action() -> Action {
    black_box(
        Action {
            tool_id: 0x1111,
            scope_index: 3,
            amount: 125_000_000,
            recipient: 0x2222,
            nonce: 0x3333,
        },
    )
}

#[test]
fn binding_follows_its_definition() {
    let action = sample_action();
    assert_eq(
        action.binding(),
        poseidon2([TAG_ACTION_BINDING, 0x1111, 3, 125_000_000, 0x2222, 0x3333]),
    );
}

#[test]
fn binding_keeps_the_full_width_of_every_integer() {
    let action = black_box(
        Action {
            tool_id: 0 - 1,
            scope_index: 255,
            amount: U128_MAX,
            recipient: 0 - 1,
            nonce: 0 - 1,
        },
    );
    assert_eq(
        action.binding(),
        poseidon2([TAG_ACTION_BINDING, 0 - 1, 255, 0xffffffffffffffffffffffffffffffff, 0 - 1, 0 - 1]),
    );
}

#[test]
fn binding_changes_with_every_field() {
    let base = sample_action();
    let binding = base.binding();

    let mut changed = base;
    changed.tool_id += 1;
    assert(changed.binding() != binding);

    let mut changed = base;
    changed.scope_index += 1;
    assert(changed.binding() != binding);

    let mut changed = base;
    changed.amount += 1;
    assert(changed.binding() != binding);

    let mut changed = base;
    changed.recipient += 1;
    assert(changed.binding() != binding);

    let mut changed = base;
    changed.nonce += 1;
    assert(changed.binding() != binding);
}

#[test]
fn binding_does_not_confuse_fields_of_the_same_type() {
    let base = sample_action();

    let mut swapped = base;
    swapped.tool_id = base.recipient;
    swapped.recipient = base.tool_id;
    assert(swapped.binding() != base.binding());

    let mut swapped = base;
    swapped.recipient = base.nonce;
    swapped.nonce = base.recipient;
    assert(swapped.binding() != base.binding());

    // scope_index and amount hold the same number in swapped places.
    let a = black_box(
        Action { tool_id: 1, scope_index: 3, amount: 5, recipient: 2, nonce: 4 },
    );
    let b = black_box(
        Action { tool_id: 1, scope_index: 5, amount: 3, recipient: 2, nonce: 4 },
    );
    assert(a.binding() != b.binding());
}

#[test]
fn binding_and_commitment_are_domain_separated() {
    let x: [Field; 5] = black_box([1, 2, 3, 4, 5]);
    assert(
        poseidon2([TAG_ACTION_BINDING, x[0], x[1], x[2], x[3], x[4]])
            != poseidon2([TAG_POLICY_COMMITMENT, x[0], x[1], x[2], x[3], x[4]]),
    );
}
