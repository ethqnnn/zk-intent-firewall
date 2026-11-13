/**
 * The hash `H` and the four protocol hashes built on it (docs/circuit-spec.md, sections 5.3-5.7).
 *
 * `H` is Barretenberg's Poseidon2 sponge, called through @aztec/bb.js. The spec records that this
 * call is byte-identical to the circuit's `Poseidon2::hash(input, input.len())`, and
 * test/vectors.test.ts checks every value of fixtures/vectors.json against it.
 */
import { BackendType, BarretenbergSync } from '@aztec/bb.js';
import {
  POLICY_VERSION,
  TAG_ACTION_BINDING,
  TAG_ALLOWLIST_LEAF,
  TAG_ALLOWLIST_NODE,
  TAG_POLICY_COMMITMENT,
  TREE_DEPTH,
} from './constants.js';
import { assertField, assertUint, bytesToField, EncodingError, fieldToBytes } from './field.js';
import type { Action, PolicyFields } from './types.js';

export class ProtocolHasher {
  #zeroHashes: readonly bigint[] | undefined;

  private constructor(private readonly bb: BarretenbergSync) {}

  /**
   * Creates a hasher on Barretenberg's WASM build. Hashing needs no reference string, so none is
   * loaded.
   */
  static async create(): Promise<ProtocolHasher> {
    const bb = await BarretenbergSync.new({ backend: BackendType.Wasm, skipSrsInit: true });
    return new ProtocolHasher(bb);
  }

  /** `H(x[0], ..., x[n-1])`, for `n >= 1` canonical field elements. */
  hash(inputs: readonly bigint[]): bigint {
    if (inputs.length === 0) throw new EncodingError('H takes at least one input');
    const encoded = inputs.map((x, i) => fieldToBytes(assertField(x, `H input ${i}`)));
    return bytesToField(this.bb.poseidon2Hash({ inputs: encoded }).hash, 'H output');
  }

  /** `leaf(recipient) = H(TAG_ALLOWLIST_LEAF, recipient)`. */
  leaf(recipient: bigint): bigint {
    return this.hash([TAG_ALLOWLIST_LEAF, recipient]);
  }

  /** `node(left, right) = H(TAG_ALLOWLIST_NODE, left, right)`. */
  node(left: bigint, right: bigint): bigint {
    return this.hash([TAG_ALLOWLIST_NODE, left, right]);
  }

  /** `Z[0] = 0`, `Z[h + 1] = node(Z[h], Z[h])`, for `h = 0 ... TREE_DEPTH`. */
  zeroHashes(): readonly bigint[] {
    if (this.#zeroHashes === undefined) {
      const z = [0n];
      for (let h = 0; h < TREE_DEPTH; h++) z.push(this.node(z[h]!, z[h]!));
      this.#zeroHashes = Object.freeze(z);
    }
    return this.#zeroHashes;
  }

  /** `H(TAG_POLICY_COMMITMENT, POLICY_VERSION, max_amount, allowlist_root, scope_mask, expiry, salt)`. */
  policyCommitment(policy: PolicyFields): bigint {
    return this.hash([
      TAG_POLICY_COMMITMENT,
      POLICY_VERSION,
      assertUint(policy.maxAmount, 128, 'max_amount'),
      assertField(policy.allowlistRoot, 'allowlist_root'),
      assertUint(policy.scopeMask, 64, 'scope_mask'),
      assertUint(policy.expiry, 64, 'expiry'),
      assertField(policy.salt, 'salt'),
    ]);
  }

  /** `H(TAG_ACTION_BINDING, tool_id, scope_index, amount, recipient, nonce)`. */
  actionBinding(action: Action): bigint {
    if (!Number.isInteger(action.scopeIndex)) throw new EncodingError('scope_index must be an integer');
    return this.hash([
      TAG_ACTION_BINDING,
      assertField(action.toolId, 'tool_id'),
      assertUint(BigInt(action.scopeIndex), 8, 'scope_index'),
      assertUint(action.amount, 128, 'amount'),
      assertField(action.recipient, 'recipient'),
      assertField(action.nonce, 'nonce'),
    ]);
  }
}

let shared: Promise<ProtocolHasher> | undefined;

/** A process-wide hasher, created on first use. */
export function getHasher(): Promise<ProtocolHasher> {
  shared ??= ProtocolHasher.create();
  return shared;
}
