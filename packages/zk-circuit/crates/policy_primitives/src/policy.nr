//! The policy a human approves, and its commitment.

use crate::constants::{POLICY_VERSION, SCOPE_BITS, TAG_POLICY_COMMITMENT};
use crate::hash::poseidon2;

/// The private policy. Only its commitment is ever public.
pub struct Policy {
    /// Largest amount allowed for a single action, in base units.
    pub max_amount: u128,
    /// Root of the recipient allowlist tree.
    pub allowlist_root: Field,
    /// Granted scopes. Bit `i` set means scope `i` is granted.
    pub scope_mask: u64,
    /// Unix time in seconds. The policy is valid strictly before this instant.
    pub expiry: u64,
    /// High-entropy blinding value. Without it a low-entropy policy could be recovered from the
    /// public commitment by brute force.
    pub salt: Field,
}

impl Policy {
    /// The policy commitment:
    /// `H(TAG_POLICY_COMMITMENT, POLICY_VERSION, max_amount, allowlist_root, scope_mask, expiry, salt)`.
    ///
    /// Integers enter the hash as the field element with the same numeric value.
    pub fn commitment(self) -> Field {
        poseidon2([
            TAG_POLICY_COMMITMENT,
            POLICY_VERSION,
            self.max_amount as Field,
            self.allowlist_root,
            self.scope_mask as Field,
            self.expiry as Field,
            self.salt,
        ])
    }

    /// Whether bit `scope_index` of `scope_mask` is set.
    ///
    /// The bit is selected by comparing `scope_index` with every position, not by indexing an
    /// array. That makes the function total: an index of `SCOPE_BITS` or more matches no position
    /// and reads as not granted. It also keeps memory lookups out of the circuit, so the compiler
    /// keeps the explicit 8-bit range constraint on `scope_index`.
    pub fn grants_scope(self, scope_index: u8) -> bool {
        let granted: [bool; SCOPE_BITS] = (self.scope_mask as Field).to_le_bits();
        let mut result = false;
        for bit in 0..SCOPE_BITS {
            result = result | (granted[bit] & (scope_index as u32 == bit));
        }
        result
    }
}
