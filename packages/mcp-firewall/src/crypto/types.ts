/** The circuit's `Policy` struct, field by field (docs/circuit-spec.md, section 4.2). */
export interface PolicyFields {
  /** u128. Largest amount allowed for one action, in base units. */
  readonly maxAmount: bigint;
  /** Field. Root of the recipient allowlist tree. */
  readonly allowlistRoot: bigint;
  /** u64. Bit `i` set means scope `i` is granted. */
  readonly scopeMask: bigint;
  /** u64. Unix seconds. The policy is valid strictly before this instant. */
  readonly expiry: bigint;
  /** Field, non-zero. High-entropy blinding value. */
  readonly salt: bigint;
}

/** The circuit's `Action` struct, field by field (docs/circuit-spec.md, section 4.2). */
export interface Action {
  /** Field. Identifier of the tool, committing to the tool server (section 10.4). */
  readonly toolId: bigint;
  /** u8, below 64. The scope this tool requires. */
  readonly scopeIndex: number;
  /** u128, non-zero. Amount in base units. */
  readonly amount: bigint;
  /** Field. Identifier of the destination, committing to network, asset and account. */
  readonly recipient: bigint;
  /** Field. Unique per call. Also blinds the binding. */
  readonly nonce: bigint;
}
