//! Tests of the circuit as a whole.
//!
//! Every test function here is constrained and calls `main` on values that come out of an
//! unconstrained helper, so the circuit's constraints are evaluated on witnesses exactly as they
//! are when a proof is made. Each rejection test breaks one thing and names the assertion that
//! must stop it.

mod accept;
mod allowlist;
mod amount;
mod binding;
mod commitment;
mod expiry;
mod helpers;
mod known_answers;
mod scope;
