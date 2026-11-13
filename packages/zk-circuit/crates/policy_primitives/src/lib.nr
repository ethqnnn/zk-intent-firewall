//! Policy primitives for the proof-of-intent circuit.
//!
//! This crate is on the security path. It only computes: it contains no assertion, no
//! `unconstrained` function and no `unsafe` block. Every constraint of the statement is asserted in
//! `proof_of_intent/src/main.nr`.
//!
//! The definitions here are normative and are mirrored in `docs/circuit-spec.md`, section 5.

pub mod action;
pub mod constants;
pub mod hash;
pub mod merkle;
pub mod policy;

mod tests;
