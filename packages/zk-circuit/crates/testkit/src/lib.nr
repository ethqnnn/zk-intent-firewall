//! Off-circuit tooling for the proof-of-intent circuit: a reference allowlist tree builder and the
//! canonical scenario behind the fixtures.
//!
//! Nothing here is on the security path. The circuit never calls this crate. Tests and the fixture
//! generator use it to build inputs, and the circuit recomputes everything it relies on.

pub mod scenario;
pub mod tree;

mod tests;
