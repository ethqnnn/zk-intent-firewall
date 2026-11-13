//! Statements the circuit must accept, including every boundary.

use super::helpers::{dense_witness, fixture, prove, reseal, single_witness};
use policy_primitives::constants::{MAX_LEAVES, SCOPE_BITS};
use testkit::scenario::ALLOWLIST;

global U64_MAX: u64 = 0xffffffffffffffff;
global U128_MAX: u128 = 0xffffffffffffffffffffffffffffffff;

#[test]
fn accepts_the_canonical_fixture() {
    prove(fixture());
}

// --- amount boundaries -----------------------------------------------------------------------

#[test]
fn accepts_amount_equal_to_the_limit() {
    let mut s = fixture();
    s.action.amount = s.policy.max_amount;
    prove(reseal(s));
}

#[test]
fn accepts_the_smallest_amount() {
    let mut s = fixture();
    s.action.amount = 1;
    prove(reseal(s));
}

#[test]
fn accepts_the_smallest_amount_at_the_smallest_useful_limit() {
    let mut s = fixture();
    s.policy.max_amount = 1;
    s.action.amount = 1;
    prove(reseal(s));
}

#[test]
fn accepts_the_largest_u128_amount_at_the_largest_limit() {
    let mut s = fixture();
    s.policy.max_amount = U128_MAX;
    s.action.amount = U128_MAX;
    prove(reseal(s));
}

#[test]
fn accepts_an_amount_one_below_the_largest_limit() {
    let mut s = fixture();
    s.policy.max_amount = U128_MAX;
    s.action.amount = U128_MAX - 1;
    prove(reseal(s));
}

#[test]
fn accepts_amounts_on_both_sides_of_the_u64_boundary() {
    let mut s = fixture();
    s.policy.max_amount = 18446744073709551616; // 2^64
    s.action.amount = 18446744073709551615; // 2^64 - 1
    prove(reseal(s));
    s.action.amount = 18446744073709551616; // 2^64
    prove(reseal(s));
}

// --- expiry boundaries -----------------------------------------------------------------------

#[test]
fn accepts_a_timestamp_one_second_before_expiry() {
    let mut s = fixture();
    s.current_timestamp = s.policy.expiry - 1;
    prove(s);
}

#[test]
fn accepts_a_timestamp_of_zero() {
    let mut s = fixture();
    s.current_timestamp = 0;
    prove(s);
}

#[test]
fn accepts_the_largest_u64_expiry() {
    let mut s = fixture();
    s.policy.expiry = U64_MAX;
    s.current_timestamp = U64_MAX - 1;
    prove(reseal(s));
}

#[test]
fn accepts_timestamps_on_both_sides_of_the_u32_boundary() {
    let mut s = fixture();
    s.policy.expiry = 4294967297; // 2^32 + 1
    s = reseal(s);
    s.current_timestamp = 4294967295; // 2^32 - 1
    prove(s);
    s.current_timestamp = 4294967296; // 2^32
    prove(s);
}

// --- allowlist boundaries --------------------------------------------------------------------

#[test]
fn accepts_the_first_leaf_index() {
    let mut s = fixture();
    let (root, path) = dense_witness(ALLOWLIST, 0);
    assert_eq(root, s.policy.allowlist_root);
    s.action.recipient = ALLOWLIST[0];
    s.leaf_index = 0;
    s.merkle_path = path;
    prove(reseal(s));
}

#[test]
fn accepts_the_last_leaf_index() {
    let mut s = fixture();
    let last = MAX_LEAVES - 1;
    let (root, path) = single_witness(s.action.recipient, last);
    s.policy.allowlist_root = root;
    s.leaf_index = last;
    s.merkle_path = path;
    prove(reseal(s));
}

#[test]
fn accepts_every_allowlisted_recipient() {
    for position in 0..5 {
        let mut s = fixture();
        let (root, path) = dense_witness(ALLOWLIST, position);
        assert_eq(root, s.policy.allowlist_root);
        s.action.recipient = ALLOWLIST[position];
        s.leaf_index = position;
        s.merkle_path = path;
        prove(reseal(s));
    }
}

#[test]
fn accepts_an_allowlist_with_a_single_recipient_at_the_first_position() {
    let mut s = fixture();
    let (root, path) = single_witness(s.action.recipient, 0);
    s.policy.allowlist_root = root;
    s.leaf_index = 0;
    s.merkle_path = path;
    prove(reseal(s));
}

// --- scope boundaries ------------------------------------------------------------------------

#[test]
fn accepts_the_lowest_and_the_highest_scope_bit() {
    let mut s = fixture();
    s.policy.scope_mask = 1 | (1 << 63);
    s.action.scope_index = 0;
    prove(reseal(s));
    s.action.scope_index = 63;
    prove(reseal(s));
}

#[test]
fn accepts_every_scope_when_every_bit_is_granted() {
    for scope in 0..SCOPE_BITS {
        let mut s = fixture();
        s.policy.scope_mask = U64_MAX;
        s.action.scope_index = scope as u8;
        prove(reseal(s));
    }
}

#[test]
fn accepts_each_scope_the_fixture_policy_grants() {
    let granted: [u8; 3] = [0, 3, 17];
    for k in 0..3 {
        let mut s = fixture();
        s.action.scope_index = granted[k];
        prove(reseal(s));
    }
}

// --- binding ---------------------------------------------------------------------------------

#[test]
fn accepts_a_nonce_of_zero_and_the_largest_field_element() {
    let mut s = fixture();
    s.action.nonce = 0;
    prove(reseal(s));
    s.action.nonce = 0 - 1;
    prove(reseal(s));
}
