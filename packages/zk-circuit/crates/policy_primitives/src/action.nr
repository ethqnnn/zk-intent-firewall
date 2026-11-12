//! The action a tool call performs, and its binding hash.

use crate::constants::TAG_ACTION_BINDING;
use crate::hash::poseidon2;

/// One tool call, as the policy sees it.
///
/// The verifier knows every field: it derives them from the call it is about to execute. They are
/// private inputs of the circuit and reach the public side only through `binding`.
pub struct Action {
    /// Identifier of the tool. It should also identify the tool server, so that a proof cannot be
    /// replayed at a different verifier.
    pub tool_id: Field,
    /// Index of the scope bit this tool requires, in `0..SCOPE_BITS`.
    pub scope_index: u8,
    /// Amount of this action, in base units.
    pub amount: u128,
    /// Identifier of the destination. It should commit to the network, the asset and the account.
    pub recipient: Field,
    /// Unique per call. It makes the proof single-use and blinds the binding.
    pub nonce: Field,
}

impl Action {
    /// The action binding:
    /// `H(TAG_ACTION_BINDING, tool_id, scope_index, amount, recipient, nonce)`.
    ///
    /// Integers enter the hash as the field element with the same numeric value.
    pub fn binding(self) -> Field {
        poseidon2([
            TAG_ACTION_BINDING,
            self.tool_id,
            self.scope_index as Field,
            self.amount as Field,
            self.recipient,
            self.nonce,
        ])
    }
}
