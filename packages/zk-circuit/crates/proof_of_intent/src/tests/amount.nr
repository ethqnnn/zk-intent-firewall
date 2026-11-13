//! C3: 0 < amount <= max_amount, as integers that cannot wrap.

use super::helpers::{fixture, prove, reseal};

global U128_MAX: u128 = 0xffffffffffffffffffffffffffffffff;

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_an_amount_one_above_the_limit() {
    let mut s = fixture();
    s.action.amount = s.policy.max_amount + 1;
    prove(reseal(s));
}

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_an_amount_far_above_the_limit() {
    let mut s = fixture();
    s.action.amount = s.policy.max_amount * 1000;
    prove(reseal(s));
}

#[test(should_fail_with = "amount must be non-zero")]
fn rejects_a_zero_amount() {
    let mut s = fixture();
    s.action.amount = 0;
    prove(reseal(s));
}

#[test(should_fail_with = "amount must be non-zero")]
fn rejects_a_zero_amount_even_when_the_limit_is_zero() {
    let mut s = fixture();
    s.policy.max_amount = 0;
    s.action.amount = 0;
    prove(reseal(s));
}

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_every_amount_when_the_limit_is_zero() {
    let mut s = fixture();
    s.policy.max_amount = 0;
    s.action.amount = 1;
    prove(reseal(s));
}

// --- values near the top of u128 -------------------------------------------------------------

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_the_largest_u128_amount_one_above_the_limit() {
    let mut s = fixture();
    s.policy.max_amount = U128_MAX - 1;
    s.action.amount = U128_MAX;
    prove(reseal(s));
}

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_the_largest_u128_amount_against_a_small_limit() {
    let mut s = fixture();
    s.action.amount = U128_MAX;
    prove(reseal(s));
}

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_the_largest_u128_amount_against_a_limit_of_zero() {
    let mut s = fixture();
    s.policy.max_amount = 0;
    s.action.amount = U128_MAX;
    prove(reseal(s));
}

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_the_top_bit_of_u128_against_a_small_limit() {
    let mut s = fixture();
    s.action.amount = 170141183460469231731687303715884105728; // 2^127
    prove(reseal(s));
}

// --- a comparison that looked only at the low 64 bits would accept these ----------------------

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_an_amount_whose_low_64_bits_are_within_the_limit() {
    let mut s = fixture();
    s.action.amount = 18446744073709551616 + 1; // 2^64 + 1
    prove(reseal(s));
}

#[test(should_fail_with = "amount exceeds policy limit")]
fn rejects_an_amount_just_across_the_u64_boundary() {
    let mut s = fixture();
    s.policy.max_amount = 18446744073709551615; // 2^64 - 1
    s.action.amount = 18446744073709551616; // 2^64
    prove(reseal(s));
}
