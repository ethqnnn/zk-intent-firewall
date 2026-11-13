//! Zero-knowledge proof of intent.
//!
//! Proves that one agent action obeys a policy a human approved, revealing only the policy
//! commitment, a timestamp and a binding hash of the action. See `docs/circuit-spec.md`.
//!
//! Every assertion of the statement is in this file. `policy_primitives` only computes.

use policy_primitives::action::Action;
use policy_primitives::constants::{MAX_LEAVES, SCOPE_BITS, TREE_DEPTH};
use policy_primitives::hash::hash_leaf;
use policy_primitives::merkle::compute_root;
use policy_primitives::policy::Policy;

mod tests;

/// Public inputs, in this order: `policy_commitment`, `current_timestamp`, `action_binding`.
/// The verifier must build all three from its own state and never accept them from the prover.
///
/// Private inputs: the policy opening, the action, and the Merkle witness for the recipient.
fn main(
    policy_commitment: pub Field,
    current_timestamp: pub u64,
    action_binding: pub Field,
    policy: Policy,
    action: Action,
    leaf_index: u32,
    merkle_path: [Field; TREE_DEPTH],
) {
    // C1. The private policy opens the public commitment.
    assert(policy.salt != 0, "policy salt must be non-zero");
    assert(policy.commitment() == policy_commitment, "policy commitment mismatch");

    // C2. The recipient is a leaf of the allowlist tree.
    assert(leaf_index < MAX_LEAVES, "leaf index out of range");
    let allowlist_root = compute_root(hash_leaf(action.recipient), leaf_index, merkle_path);
    assert(allowlist_root == policy.allowlist_root, "recipient not in allowlist");

    // C3. The amount is within bounds: 0 < amount <= max_amount.
    assert(action.amount != 0, "amount must be non-zero");
    assert(action.amount <= policy.max_amount, "amount exceeds policy limit");

    // C4. The scope this tool requires is granted.
    assert((action.scope_index as u32) < SCOPE_BITS, "scope index out of range");
    assert(policy.grants_scope(action.scope_index), "scope not granted by policy");

    // C5. The policy has not expired. The verifier checks that the timestamp is fresh.
    assert(current_timestamp < policy.expiry, "policy expired");

    // C6. The proof is bound to exactly this action.
    assert(action.binding() == action_binding, "action binding mismatch");
}
