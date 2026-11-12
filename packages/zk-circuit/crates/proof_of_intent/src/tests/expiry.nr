//! C5: current_timestamp < expiry, strictly.

use super::helpers::{fixture, prove, reseal};

global U64_MAX: u64 = 0xffffffffffffffff;

#[test(should_fail_with = "policy expired")]
fn rejects_a_timestamp_equal_to_expiry() {
    let mut s = fixture();
    s.current_timestamp = s.policy.expiry;
    prove(s);
}

#[test(should_fail_with = "policy expired")]
fn rejects_a_timestamp_one_second_after_expiry() {
    let mut s = fixture();
    s.current_timestamp = s.policy.expiry + 1;
    prove(s);
}

#[test(should_fail_with = "policy expired")]
fn rejects_a_timestamp_long_after_expiry() {
    let mut s = fixture();
    s.current_timestamp = s.policy.expiry + 315360000; // ten years
    prove(s);
}

#[test(should_fail_with = "policy expired")]
fn rejects_an_expiry_of_zero() {
    let mut s = fixture();
    s.policy.expiry = 0;
    s.current_timestamp = 0;
    prove(reseal(s));
}

// --- values near the top of u64 --------------------------------------------------------------

#[test(should_fail_with = "policy expired")]
fn rejects_the_largest_u64_timestamp_at_the_largest_expiry() {
    let mut s = fixture();
    s.policy.expiry = U64_MAX;
    s.current_timestamp = U64_MAX;
    prove(reseal(s));
}

#[test(should_fail_with = "policy expired")]
fn rejects_the_largest_u64_timestamp_against_a_normal_expiry() {
    let mut s = fixture();
    s.current_timestamp = U64_MAX;
    prove(s);
}

#[test(should_fail_with = "policy expired")]
fn rejects_the_largest_u64_timestamp_one_above_expiry() {
    let mut s = fixture();
    s.policy.expiry = U64_MAX - 1;
    s.current_timestamp = U64_MAX;
    prove(reseal(s));
}

// --- a comparison that looked only at the low 32 bits would accept this -----------------------

#[test(should_fail_with = "policy expired")]
fn rejects_a_timestamp_whose_low_32_bits_are_before_expiry() {
    let mut s = fixture();
    s.current_timestamp = 4294967296 + 1; // 2^32 + 1, later than the expiry in 2027
    prove(s);
}
