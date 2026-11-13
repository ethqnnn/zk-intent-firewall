//! Shared helpers for the circuit tests.

use crate::main;
use policy_primitives::constants::TREE_DEPTH;
use testkit::scenario::{canonical, Scenario};
use testkit::tree::{dense_allowlist, single_recipient_allowlist};

/// Runs the circuit on a scenario.
pub(crate) fn prove(s: Scenario) {
    main(
        s.policy_commitment,
        s.current_timestamp,
        s.action_binding,
        s.policy,
        s.action,
        s.leaf_index,
        s.merkle_path,
    );
}

/// The canonical valid scenario, identical to `fixtures/Prover.toml`.
pub(crate) fn fixture() -> Scenario {
    // Safety: this only builds test inputs. The circuit recomputes everything it relies on.
    unsafe {
        canonical()
    }
}

/// Recomputes both public hashes after an honest change to the policy or the action.
pub(crate) fn reseal(mut s: Scenario) -> Scenario {
    s.policy_commitment = s.policy.commitment();
    s.action_binding = s.action.binding();
    s
}

/// Root of the allowlist holding `recipients[k]` at position `k`, and the path of `target`.
pub(crate) fn dense_witness<let N: u32>(
    recipients: [Field; N],
    target: u32,
) -> (Field, [Field; TREE_DEPTH]) {
    // Safety: this only builds test inputs. The circuit recomputes the root from the path.
    unsafe {
        dense_allowlist(recipients, target)
    }
}

/// Root of the allowlist holding one recipient at `position`, and the path of that position.
pub(crate) fn single_witness(recipient: Field, position: u32) -> (Field, [Field; TREE_DEPTH]) {
    // Safety: this only builds test inputs. The circuit recomputes the root from the path.
    unsafe {
        single_recipient_allowlist(recipient, position)
    }
}
