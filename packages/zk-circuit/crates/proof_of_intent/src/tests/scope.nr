//! C4: the scope bit the tool requires must be set in the policy's scope mask.
//!
//! The fixture policy grants scopes 0, 3 and 17.

use super::helpers::{fixture, prove, reseal};

#[test(should_fail_with = "scope not granted by policy")]
fn rejects_a_scope_that_is_not_granted() {
    let mut s = fixture();
    s.action.scope_index = 9;
    prove(reseal(s));
}

#[test(should_fail_with = "scope not granted by policy")]
fn rejects_the_scope_one_below_a_granted_bit() {
    let mut s = fixture();
    s.action.scope_index = 2;
    prove(reseal(s));
}

#[test(should_fail_with = "scope not granted by policy")]
fn rejects_the_scope_one_above_a_granted_bit() {
    let mut s = fixture();
    s.action.scope_index = 4;
    prove(reseal(s));
}

#[test(should_fail_with = "scope not granted by policy")]
fn rejects_every_scope_when_the_mask_is_empty() {
    let mut s = fixture();
    s.policy.scope_mask = 0;
    prove(reseal(s));
}

#[test(should_fail_with = "scope not granted by policy")]
fn rejects_a_scope_whose_bit_was_cleared() {
    let mut s = fixture();
    // Every bit except the one the action needs.
    s.policy.scope_mask = 0xffffffffffffffff ^ (1 << 3);
    prove(reseal(s));
}

// --- a mask read in the wrong bit order would accept these -----------------------------------

#[test(should_fail_with = "scope not granted by policy")]
fn rejects_the_highest_scope_when_only_the_lowest_is_granted() {
    let mut s = fixture();
    s.policy.scope_mask = 1;
    s.action.scope_index = 63;
    prove(reseal(s));
}

#[test(should_fail_with = "scope not granted by policy")]
fn rejects_the_lowest_scope_when_only_the_highest_is_granted() {
    let mut s = fixture();
    s.policy.scope_mask = 1 << 63;
    s.action.scope_index = 0;
    prove(reseal(s));
}

// --- index range -----------------------------------------------------------------------------

#[test(should_fail_with = "scope index out of range")]
fn rejects_a_scope_index_equal_to_the_mask_width() {
    let mut s = fixture();
    s.policy.scope_mask = 0xffffffffffffffff;
    s.action.scope_index = 64;
    prove(reseal(s));
}

#[test(should_fail_with = "scope index out of range")]
fn rejects_a_scope_index_that_aliases_a_granted_one_in_its_low_bits() {
    let mut s = fixture();
    // 67 is 64 + 3, and scope 3 is granted.
    s.action.scope_index = 67;
    prove(reseal(s));
}

#[test(should_fail_with = "scope index out of range")]
fn rejects_the_largest_u8_scope_index() {
    let mut s = fixture();
    s.policy.scope_mask = 0xffffffffffffffff;
    s.action.scope_index = 255;
    prove(reseal(s));
}
