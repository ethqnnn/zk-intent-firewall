//! C6: the proof is bound to one action.
//!
//! In each test the public `action_binding` is what the verifier computed from the call in front of
//! it, and the prover tries to satisfy the circuit with a different action that is itself allowed
//! by the policy. Only the binding can object.

use super::helpers::{dense_witness, fixture, prove};
use policy_primitives::constants::{TAG_ACTION_BINDING, TAG_POLICY_COMMITMENT};
use policy_primitives::hash::poseidon2;
use testkit::scenario::{ALLOWLIST, OTHER_NONCE, TOOL_REFUND_PAYMENT};

// --- each action field changed on its own ----------------------------------------------------

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_made_for_a_different_tool() {
    let mut s = fixture();
    s.action.tool_id = TOOL_REFUND_PAYMENT;
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_made_for_a_different_scope() {
    let mut s = fixture();
    // Scope 17 is granted too.
    s.action.scope_index = 17;
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_made_for_a_different_amount() {
    let mut s = fixture();
    s.action.amount -= 1;
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_made_for_a_larger_amount_within_the_limit() {
    let mut s = fixture();
    s.action.amount = s.policy.max_amount;
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_made_for_a_different_recipient() {
    let mut s = fixture();
    // Another member of the allowlist, with its own valid path.
    let (root, path) = dense_witness(ALLOWLIST, 1);
    assert_eq(root, s.policy.allowlist_root);
    s.action.recipient = ALLOWLIST[1];
    s.leaf_index = 1;
    s.merkle_path = path;
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_made_for_a_different_nonce() {
    let mut s = fixture();
    s.action.nonce = OTHER_NONCE;
    prove(s);
}

// --- the public binding itself ---------------------------------------------------------------

#[test(should_fail_with = "action binding mismatch")]
fn rejects_an_unrelated_public_binding() {
    let mut s = fixture();
    s.action_binding = 12345;
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_the_policy_commitment_presented_as_the_binding() {
    let mut s = fixture();
    s.action_binding = s.policy_commitment;
    prove(s);
}

#[test]
fn binding_preimage_reproduces_the_real_binding() {
    let s = fixture();
    assert_eq(
        poseidon2([
            TAG_ACTION_BINDING,
            s.action.tool_id,
            s.action.scope_index as Field,
            s.action.amount as Field,
            s.action.recipient,
            s.action.nonce,
        ]),
        s.action_binding,
    );
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_made_with_another_domain_tag() {
    let mut s = fixture();
    s.action_binding = poseidon2([
        TAG_POLICY_COMMITMENT,
        s.action.tool_id,
        s.action.scope_index as Field,
        s.action.amount as Field,
        s.action.recipient,
        s.action.nonce,
    ]);
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_with_tool_and_recipient_swapped() {
    let mut s = fixture();
    s.action_binding = poseidon2([
        TAG_ACTION_BINDING,
        s.action.recipient,
        s.action.scope_index as Field,
        s.action.amount as Field,
        s.action.tool_id,
        s.action.nonce,
    ]);
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_that_leaves_out_the_scope() {
    let mut s = fixture();
    s.action_binding = poseidon2([
        TAG_ACTION_BINDING,
        s.action.tool_id,
        s.action.amount as Field,
        s.action.recipient,
        s.action.nonce,
    ]);
    prove(s);
}

#[test(should_fail_with = "action binding mismatch")]
fn rejects_a_binding_that_leaves_out_the_nonce() {
    let mut s = fixture();
    s.action_binding = poseidon2([
        TAG_ACTION_BINDING,
        s.action.tool_id,
        s.action.scope_index as Field,
        s.action.amount as Field,
        s.action.recipient,
    ]);
    prove(s);
}
