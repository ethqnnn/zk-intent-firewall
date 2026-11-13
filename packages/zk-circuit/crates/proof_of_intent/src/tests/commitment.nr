//! C1: the private policy must open the public commitment.
//!
//! A prover that lies about any part of the policy is stopped here, because the verifier holds the
//! commitment the human approved.

use super::helpers::{fixture, prove, reseal, single_witness};
use policy_primitives::constants::{POLICY_VERSION, TAG_ACTION_BINDING, TAG_POLICY_COMMITMENT};
use policy_primitives::hash::poseidon2;
use testkit::scenario::{OUTSIDER, Scenario};

// --- each policy field tampered on its own ---------------------------------------------------

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_tampered_max_amount() {
    let mut s = fixture();
    s.policy.max_amount += 1;
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_lowered_max_amount() {
    let mut s = fixture();
    // Still at least the amount, so only the commitment can object.
    s.policy.max_amount = s.action.amount;
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_tampered_allowlist_root() {
    let mut s = fixture();
    // A different tree that also holds the recipient at the same position, with a valid path, so
    // only the commitment can object.
    let (root, path) = single_witness(s.action.recipient, s.leaf_index);
    assert(root != s.policy.allowlist_root);
    s.policy.allowlist_root = root;
    s.merkle_path = path;
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_tampered_scope_mask() {
    let mut s = fixture();
    s.policy.scope_mask = s.policy.scope_mask | (1 << 5);
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_tampered_expiry() {
    let mut s = fixture();
    s.policy.expiry += 1;
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_wrong_salt() {
    let mut s = fixture();
    s.policy.salt += 1;
    prove(s);
}

// --- the salt must be present ----------------------------------------------------------------

#[test(should_fail_with = "policy salt must be non-zero")]
fn rejects_a_zero_salt_even_when_the_commitment_matches() {
    let mut s = fixture();
    s.policy.salt = 0;
    prove(reseal(s));
}

// --- the attacks those checks exist for ------------------------------------------------------

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_overspending_with_a_forged_limit() {
    let mut s = fixture();
    s.action.amount = s.policy.max_amount + 1;
    s.policy.max_amount = s.action.amount;
    s.action_binding = s.action.binding();
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_paying_an_outsider_with_a_forged_allowlist() {
    let mut s = fixture();
    let (root, path) = single_witness(OUTSIDER, 0);
    s.policy.allowlist_root = root;
    s.action.recipient = OUTSIDER;
    s.leaf_index = 0;
    s.merkle_path = path;
    s.action_binding = s.action.binding();
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_an_ungranted_scope_with_a_forged_mask() {
    let mut s = fixture();
    s.action.scope_index = 9;
    s.policy.scope_mask = s.policy.scope_mask | (1 << 9);
    s.action_binding = s.action.binding();
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_an_expired_policy_with_a_forged_expiry() {
    let mut s = fixture();
    s.current_timestamp = s.policy.expiry + 3600;
    s.policy.expiry = s.current_timestamp + 1;
    prove(s);
}

// --- the public commitment itself ------------------------------------------------------------

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_the_commitment_of_a_different_policy() {
    let mut s = fixture();
    let mut other = s.policy;
    other.max_amount = 1;
    s.policy_commitment = other.commitment();
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_an_unrelated_public_commitment() {
    let mut s = fixture();
    s.policy_commitment = 12345;
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_the_action_binding_presented_as_the_commitment() {
    let mut s = fixture();
    s.policy_commitment = s.action_binding;
    prove(s);
}

/// The commitment preimage of the scenario's policy, with a chosen tag and version.
fn commitment_with(s: Scenario, tag: Field, version: Field) -> Field {
    poseidon2([
        tag,
        version,
        s.policy.max_amount as Field,
        s.policy.allowlist_root,
        s.policy.scope_mask as Field,
        s.policy.expiry as Field,
        s.policy.salt,
    ])
}

#[test]
fn commitment_helper_reproduces_the_real_commitment() {
    let s = fixture();
    assert_eq(commitment_with(s, TAG_POLICY_COMMITMENT, POLICY_VERSION), s.policy_commitment);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_commitment_made_under_another_policy_version() {
    let mut s = fixture();
    s.policy_commitment = commitment_with(s, TAG_POLICY_COMMITMENT, POLICY_VERSION + 1);
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_commitment_made_with_another_domain_tag() {
    let mut s = fixture();
    s.policy_commitment = commitment_with(s, TAG_ACTION_BINDING, POLICY_VERSION);
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_commitment_without_the_version() {
    let mut s = fixture();
    s.policy_commitment = poseidon2([
        TAG_POLICY_COMMITMENT,
        s.policy.max_amount as Field,
        s.policy.allowlist_root,
        s.policy.scope_mask as Field,
        s.policy.expiry as Field,
        s.policy.salt,
    ]);
    prove(s);
}

#[test(should_fail_with = "policy commitment mismatch")]
fn rejects_a_commitment_with_scope_mask_and_expiry_swapped() {
    let mut s = fixture();
    s.policy_commitment = poseidon2([
        TAG_POLICY_COMMITMENT,
        POLICY_VERSION,
        s.policy.max_amount as Field,
        s.policy.allowlist_root,
        s.policy.expiry as Field,
        s.policy.scope_mask as Field,
        s.policy.salt,
    ]);
    prove(s);
}
