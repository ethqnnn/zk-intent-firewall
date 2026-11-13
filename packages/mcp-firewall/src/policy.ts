/**
 * A policy opening: everything the prover needs and the verifier must never see (spec section 2).
 */
import type { CircuitInputs } from './circuit.js';
import { SCOPE_BITS, TREE_DEPTH } from './crypto/constants.js';
import { assertField, assertUint, EncodingError, fieldToHex, parseField, parseUint } from './crypto/field.js';
import type { ProtocolHasher } from './crypto/hash.js';
import { randomSalt, recipientId } from './crypto/identifiers.js';
import { type AllowlistOrder, AllowlistTree } from './crypto/merkle.js';
import type { Action, PolicyFields } from './crypto/types.js';

/** A destination named by a CAIP-19 asset and a CAIP-10 account (spec 10.4). */
export interface RecipientRef {
  readonly assetId: string;
  readonly accountId: string;
}

export function resolveRecipient(r: bigint | RecipientRef): bigint {
  return typeof r === 'bigint' ? assertField(r, 'recipient') : recipientId(r.assetId, r.accountId);
}

export interface PolicyDefinition {
  /** Largest amount for a single action, in base units (u128). */
  readonly maxAmount: bigint;
  /** The allowed destinations. */
  readonly recipients: readonly (bigint | RecipientRef)[];
  /** Granted scope bit positions, each in [0, 64). */
  readonly scopes: readonly number[];
  /** Unix seconds (u64). Valid strictly before this instant. */
  readonly expiry: bigint;
  /** Non-zero blinding value. Omit to draw a fresh one from the CSPRNG; never reuse one. */
  readonly salt?: bigint;
  /** Placement of recipients in the tree. Default `sorted`. */
  readonly allowlistOrder?: AllowlistOrder;
}

/** Why an action is outside a policy. Mirrors the circuit's assertions C2 to C5. */
export type PolicyViolation =
  | 'recipient_not_allowlisted'
  | 'amount_zero'
  | 'amount_exceeds_limit'
  | 'scope_out_of_range'
  | 'scope_not_granted'
  | 'policy_expired';

export function scopeMaskOf(scopes: readonly number[]): bigint {
  let mask = 0n;
  for (const s of scopes) {
    if (!Number.isInteger(s) || s < 0 || s >= SCOPE_BITS) throw new EncodingError(`scope ${s} is not in [0, ${SCOPE_BITS})`);
    mask |= 1n << BigInt(s);
  }
  return mask;
}

/** JSON form of a policy opening, for storage the agent cannot reach. It contains the salt. */
export interface PolicyOpeningJson {
  readonly version: 1;
  readonly maxAmount: string;
  readonly recipients: readonly string[];
  readonly allowlistOrder: AllowlistOrder;
  readonly scopes: readonly number[];
  readonly expiry: string;
  readonly salt: string;
}

export class PolicyOpening {
  readonly fields: PolicyFields;
  readonly commitment: bigint;
  readonly tree: AllowlistTree;
  readonly scopes: readonly number[];
  readonly #order: AllowlistOrder;

  private constructor(fields: PolicyFields, tree: AllowlistTree, scopes: number[], order: AllowlistOrder, commitment: bigint) {
    this.fields = Object.freeze(fields);
    this.tree = tree;
    this.scopes = Object.freeze(scopes);
    this.#order = order;
    this.commitment = commitment;
  }

  static create(hasher: ProtocolHasher, def: PolicyDefinition): PolicyOpening {
    const salt = def.salt ?? randomSalt();
    assertField(salt, 'salt');
    if (salt === 0n) throw new EncodingError('policy salt must be non-zero');
    const order = def.allowlistOrder ?? 'sorted';
    const tree = AllowlistTree.build(hasher, def.recipients.map(resolveRecipient), order);
    const scopes = [...new Set(def.scopes)].sort((a, b) => a - b);
    const fields: PolicyFields = {
      maxAmount: assertUint(def.maxAmount, 128, 'max_amount'),
      allowlistRoot: tree.root,
      scopeMask: scopeMaskOf(scopes),
      expiry: assertUint(def.expiry, 64, 'expiry'),
      salt,
    };
    return new PolicyOpening(fields, tree, scopes, order, hasher.policyCommitment(fields));
  }

  static fromJSON(hasher: ProtocolHasher, json: PolicyOpeningJson): PolicyOpening {
    if (json.version !== 1) throw new EncodingError('unsupported policy opening version');
    return PolicyOpening.create(hasher, {
      maxAmount: parseUint(json.maxAmount, 128, 'maxAmount'),
      recipients: json.recipients.map((r, i) => parseField(r, `recipients[${i}]`)),
      scopes: json.scopes,
      expiry: parseUint(json.expiry, 64, 'expiry'),
      salt: parseField(json.salt, 'salt'),
      allowlistOrder: json.allowlistOrder,
    });
  }

  toJSON(): PolicyOpeningJson {
    return {
      version: 1,
      maxAmount: this.fields.maxAmount.toString(),
      recipients: this.tree.recipients.map(fieldToHex),
      allowlistOrder: this.#order,
      scopes: this.scopes,
      expiry: this.fields.expiry.toString(),
      salt: fieldToHex(this.fields.salt),
    };
  }

  grantsScope(scopeIndex: number): boolean {
    return Number.isInteger(scopeIndex) && scopeIndex >= 0 && scopeIndex < SCOPE_BITS && ((this.fields.scopeMask >> BigInt(scopeIndex)) & 1n) === 1n;
  }

  /**
   * The first policy rule the action breaks at `timestamp`, or undefined. The circuit is the
   * authority; this only lets the firewall refuse early, without spending a proof.
   */
  check(action: Action, timestamp: bigint): PolicyViolation | undefined {
    if (!this.tree.has(action.recipient)) return 'recipient_not_allowlisted';
    if (action.amount === 0n) return 'amount_zero';
    if (action.amount > this.fields.maxAmount) return 'amount_exceeds_limit';
    if (!Number.isInteger(action.scopeIndex) || action.scopeIndex < 0 || action.scopeIndex >= SCOPE_BITS) return 'scope_out_of_range';
    if (!this.grantsScope(action.scopeIndex)) return 'scope_not_granted';
    if (timestamp >= this.fields.expiry) return 'policy_expired';
    return undefined;
  }

  /**
   * The complete circuit inputs for an action. An action whose recipient is not allowlisted has no
   * Merkle witness; it gets the empty-tree path of position 0, and the circuit rejects it with
   * `recipient not in allowlist`.
   */
  circuitInputs(hasher: ProtocolHasher, action: Action, timestamp: bigint): CircuitInputs {
    const witness = this.tree.witness(action.recipient) ?? { leafIndex: 0, path: hasher.zeroHashes().slice(0, TREE_DEPTH) };
    return {
      policyCommitment: this.commitment,
      currentTimestamp: timestamp,
      actionBinding: hasher.actionBinding(action),
      policy: this.fields,
      action,
      leafIndex: witness.leafIndex,
      merklePath: witness.path,
    };
  }
}
