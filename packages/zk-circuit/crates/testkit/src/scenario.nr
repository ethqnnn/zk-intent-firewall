//! The canonical scenario: one valid policy, allowlist and action.
//!
//! It is the single source of the inputs in `fixtures/Prover.toml` and `fixtures/vectors.json`, and
//! the starting point of every circuit test.
//!
//! The identifiers below are test data, not secrets. They follow the encoding recommended in
//! `docs/circuit-spec.md`, section 10.4:
//!
//! ```text
//! to_field(domain, part_1, ..., part_k) =
//!     the first 31 bytes of SHA-256(domain || 0x0A || part_1 || 0x0A || ... || part_k),
//!     read as a big-endian integer
//! ```
//!
//! Reproduce one with: `printf 'zkif.fixture.v1\npolicy-salt' | sha256sum | cut -c1-62`.

use crate::tree::dense_allowlist;
use policy_primitives::action::Action;
use policy_primitives::constants::TREE_DEPTH;
use policy_primitives::policy::Policy;

/// A complete set of circuit inputs.
pub struct Scenario {
    pub policy_commitment: Field,
    pub current_timestamp: u64,
    pub action_binding: Field,
    pub policy: Policy,
    pub action: Action,
    pub leaf_index: u32,
    pub merkle_path: [Field; TREE_DEPTH],
}

// `to_field("zkif.recipient.v1", ASSET, ACCOUNT)` with
// ASSET   = "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" (CAIP-19)
// ACCOUNT = "eip155:1:0x" followed by forty times the digit d (CAIP-10), for d = 1, 2, 3, 4, 5.
/// The five allowlisted recipients. `ALLOWLIST[k]` sits at tree position `k`.
pub global ALLOWLIST: [Field; 5] = [
    0xc6961855c0b7ce72efbdcdb295060d757e94f0ef28a76a038e38ad09dcdf1e,
    0xa7e1fdd73ddc75bb6d60b0589d41d87a8275f3b7ac533e5424213844b72ce9,
    0xeac0bf957bdd6b66d1414bc75a7bf09e59269f4a79a195d0eaaef7344546fc,
    0xe48c8a9ff7876aa2838d4553d412046145d3577118c124ff1b66552e953476,
    0x98c0e0488d02768764402c9af0c424a9071d4c825481503baf61c8075b7190,
];

/// A recipient that is not on the allowlist: the same derivation with the digit 9.
pub global OUTSIDER: Field = 0xc7df553d4bf15854f17ad3e244ff85f79d212954d5e2909d407e8cb4dccb00;

/// `to_field("zkif.tool.v1", "https://payments.example.com/mcp", "send_payment")`.
pub global TOOL_SEND_PAYMENT: Field =
    0xdcd5f7cc1debd52b292ae1b578cc489f1a22baba9373db1d0ba98e2b1a29fd;

/// `to_field("zkif.tool.v1", "https://payments.example.com/mcp", "refund_payment")`.
pub global TOOL_REFUND_PAYMENT: Field =
    0x39aaafcb2d6728af8ab393a9c5d6a081a1f20a24b5bc32991210c8a9d6b0d5;

/// `to_field("zkif.fixture.v1", "policy-salt")`. A real salt comes from a random source.
pub global POLICY_SALT: Field = 0x3f744004d7afbe537c279eadb68dd8bbfc1c9f11cd7e3c4c07b25b39f20c16;

/// `to_field("zkif.fixture.v1", "nonce-0001")`. A real nonce comes from a random source.
pub global NONCE: Field = 0x7f3c70cad33913e746a9a9ffc081bfafc27753014c4368ac0615fa378b5dc0;

/// `to_field("zkif.fixture.v1", "nonce-0002")`.
pub global OTHER_NONCE: Field = 0xfd7e42f0e6920839b40131b068608118c903e0b49134d27151897b0dc35f3a;

/// 500 units of a token with six decimals.
pub global MAX_AMOUNT: u128 = 500_000_000;

/// 125 units of the same token.
pub global AMOUNT: u128 = 125_000_000;

/// Scopes 0, 3 and 17 are granted.
pub global SCOPE_MASK: u64 = 131081;

/// The scope the fixture action requires.
pub global SCOPE_INDEX: u8 = 3;

/// 2027-01-01T00:00:00Z.
pub global EXPIRY: u64 = 1798761600;

/// 2026-11-12T00:00:00Z.
pub global NOW: u64 = 1794441600;

/// Tree position of the recipient of the fixture action.
pub global LEAF_INDEX: u32 = 3;

/// The canonical valid scenario: `ALLOWLIST[LEAF_INDEX]` is paid `AMOUNT` through
/// `TOOL_SEND_PAYMENT` under scope `SCOPE_INDEX` at time `NOW`.
pub unconstrained fn canonical() -> Scenario {
    let (allowlist_root, merkle_path) = dense_allowlist(ALLOWLIST, LEAF_INDEX);
    let policy = Policy {
        max_amount: MAX_AMOUNT,
        allowlist_root,
        scope_mask: SCOPE_MASK,
        expiry: EXPIRY,
        salt: POLICY_SALT,
    };
    let action = Action {
        tool_id: TOOL_SEND_PAYMENT,
        scope_index: SCOPE_INDEX,
        amount: AMOUNT,
        recipient: ALLOWLIST[LEAF_INDEX],
        nonce: NONCE,
    };
    Scenario {
        policy_commitment: policy.commitment(),
        current_timestamp: NOW,
        action_binding: action.binding(),
        policy,
        action,
        leaf_index: LEAF_INDEX,
        merkle_path,
    }
}
