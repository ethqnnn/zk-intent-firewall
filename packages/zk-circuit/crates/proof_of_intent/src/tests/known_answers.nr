//! Known answers, copied from `fixtures/vectors.json`.
//!
//! The fixtures are printed by unconstrained code. These tests recompute the same values in
//! constrained code and compare them with literals, so they fail if the hash, a tag, an encoding
//! or the tree layout ever changes, and if the constrained and unconstrained code paths of the
//! sponge ever disagree. The same literals were reproduced outside this repository with
//! `@aztec/bb.js` and `@zkpassport/poseidon2`.
//!
//! If one of these tests fails after a toolchain or dependency upgrade, the protocol has changed.
//! Do not update the literals without understanding why.

use super::helpers::{dense_witness, fixture, prove};
use policy_primitives::action::Action;
use policy_primitives::constants::TREE_DEPTH;
use policy_primitives::hash::{hash_leaf, hash_node, poseidon2};
use policy_primitives::merkle::compute_root;
use policy_primitives::policy::Policy;
use std::hint::black_box;
use testkit::scenario::ALLOWLIST;

global POLICY_COMMITMENT: Field =
    0x2ff178b78ec3c179fd71a1c93c630bc7dcaf7fa9695580ab884ec17001ee53f3;
global ACTION_BINDING: Field = 0x0e6c766361f114f008b6b0f09e2c7136e6cdcdddb87271dea63da900bde45db6;
global ALLOWLIST_ROOT: Field = 0x13bd65f8f3f6556b8b35dc5453e37f71fb31712c0563176c525170b284d76618;
global LEAVES: [Field; 5] = [
    0x27e6ae5b42450910e5331fbb349da20f6ae1b7bbe3163c3be5490adbae9b630a,
    0x037dce996e6856ef364ff322847d55e9942d4f5f1113650f1df948fd8ea060cb,
    0x09829e35a1ade5729204533bf760ef2f94c00f0e1c400add55ae463f9d4231ed,
    0x2c275927ae983583e825fb8d74709f7153e65a29bcc479d4315301077ab74194,
    0x236b83a2e6956ab526cf78c9f1abc043986f57be3027a30bdbf5707ed44edb68,
];
/// `Z[1]`, the value of an empty subtree of height 1.
global ZERO_HASH_1: Field = 0x134def432e5efac671261862f233c6435ba884223d4db64efbe150f5f8f577af;
/// `Z[20]`, the root of an empty allowlist.
global EMPTY_ROOT: Field = 0x085069f0c87bd2611b2047fc1f475c603bd09a15788b6de66f19f3017b5b6604;

#[test]
fn fixture_public_inputs_match_known_answers() {
    let s = fixture();
    assert_eq(s.policy_commitment, POLICY_COMMITMENT);
    assert_eq(s.action_binding, ACTION_BINDING);
    assert_eq(s.current_timestamp, 1794441600);
    assert_eq(s.policy.allowlist_root, ALLOWLIST_ROOT);
}

#[test]
fn constrained_hashes_of_the_fixture_match_known_answers() {
    let s = fixture();
    assert_eq(s.policy.commitment(), POLICY_COMMITMENT);
    assert_eq(s.action.binding(), ACTION_BINDING);
    assert_eq(
        compute_root(hash_leaf(s.action.recipient), s.leaf_index, s.merkle_path),
        ALLOWLIST_ROOT,
    );
}

#[test]
fn circuit_accepts_the_known_answers_as_public_inputs() {
    let mut s = fixture();
    s.policy_commitment = POLICY_COMMITMENT;
    s.action_binding = ACTION_BINDING;
    s.policy.allowlist_root = ALLOWLIST_ROOT;
    prove(s);
}

#[test]
fn leaf_hashes_match_known_answers() {
    let recipients = black_box(ALLOWLIST);
    for position in 0..5 {
        assert_eq(hash_leaf(recipients[position]), LEAVES[position]);
    }
}

#[test]
fn allowlist_root_matches_known_answer_from_every_member() {
    for position in 0..5 {
        let (root, path) = dense_witness(ALLOWLIST, position);
        assert_eq(root, ALLOWLIST_ROOT);
        assert_eq(compute_root(LEAVES[position], position, path), ALLOWLIST_ROOT);
    }
}

#[test]
fn zero_hashes_match_known_answers() {
    let empty: Field = black_box(0);
    let mut zero = empty;
    zero = hash_node(zero, zero);
    assert_eq(zero, ZERO_HASH_1);
    for _ in 1..TREE_DEPTH {
        zero = hash_node(zero, zero);
    }
    assert_eq(zero, EMPTY_ROOT);
}

#[test]
fn poseidon2_matches_known_answers_for_every_length_in_use() {
    let x: [Field; 7] = black_box([1, 2, 3, 4, 5, 6, 7]);
    assert_eq(
        poseidon2([x[0], x[1]]),
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
    );
    assert_eq(
        poseidon2([x[0], x[1], x[2]]),
        0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8,
    );
    assert_eq(
        poseidon2([x[0], x[1], x[2], x[3], x[4], x[5]]),
        0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a,
    );
    assert_eq(poseidon2(x), 0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238);
}

#[test]
fn edge_case_commitments_match_known_answers() {
    let largest: Field = 0 - 1;
    let top = black_box(
        Policy {
            max_amount: 0xffffffffffffffffffffffffffffffff,
            allowlist_root: largest,
            scope_mask: 0xffffffffffffffff,
            expiry: 0xffffffffffffffff,
            salt: largest,
        },
    );
    assert_eq(top.commitment(), 0x241fbacfc8fcf1c34a2707a0eb54dcfefe8d79a9b879d8741a46dab57c4e17de);

    let bottom = black_box(
        Policy { max_amount: 0, allowlist_root: 0, scope_mask: 0, expiry: 0, salt: 1 },
    );
    assert_eq(
        bottom.commitment(),
        0x2fe6745202e782bc643fea08630340cf9c3233902dedfe961724a27d623e40e4,
    );

    let mixed = black_box(
        Policy {
            max_amount: 18446744073709551616, // 2^64
            allowlist_root: EMPTY_ROOT,
            scope_mask: 9223372036854775808, // 2^63
            expiry: 4294967296, // 2^32
            salt: 452312848583266388373324160190187140051835877600158453279131187530910662655, // 2^248 - 1
        },
    );
    assert_eq(
        mixed.commitment(),
        0x0bcfe9a663c9c02bf8fb2e7dacee320ceeb27479592a3233dcedcc8c651b8ac1,
    );
}

#[test]
fn edge_case_bindings_match_known_answers() {
    let largest: Field = 0 - 1;
    let top = black_box(
        Action {
            tool_id: largest,
            scope_index: 63,
            amount: 0xffffffffffffffffffffffffffffffff,
            recipient: largest,
            nonce: largest,
        },
    );
    assert_eq(top.binding(), 0x1ec26e14e3689ff7b3b4a92918093f0ad6c08e0e6434bd1209877b0922acd720);

    let bottom = black_box(
        Action { tool_id: 0, scope_index: 0, amount: 1, recipient: 0, nonce: 0 },
    );
    assert_eq(bottom.binding(), 0x1234cfb152f397c42802c3b3417ce24429867198ae60f3c51d4b0bb4906d2e52);

    let mixed = black_box(
        Action {
            tool_id: 452312848583266388373324160190187140051835877600158453279131187530910662655, // 2^248 - 1
            scope_index: 32,
            amount: 18446744073709551616, // 2^64
            recipient: 1461501637330902918203684832716283019655932542975, // 2^160 - 1
            nonce: 340282366920938463463374607431768211455, // 2^128 - 1
        },
    );
    assert_eq(mixed.binding(), 0x05bd511277401c0bafe06c78e9578576479b7236600fa66f66b58c28097ef303);
}
