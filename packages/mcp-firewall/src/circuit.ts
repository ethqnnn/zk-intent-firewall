/**
 * The compiled proof_of_intent circuit, its pinned verification keys, and the mapping from typed
 * inputs to the circuit's ABI (docs/circuit-spec.md, section 4).
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { CompiledCircuit, InputMap } from '@noir-lang/noir_js';
import { TREE_DEPTH } from './crypto/constants.js';
import { assertField, assertUint, fieldToHex } from './crypto/field.js';
import type { Action, PolicyFields } from './crypto/types.js';

/**
 * The zero-knowledge verifier targets. `*-no-zk` targets leak the witness, which here is the
 * policy, so they are not representable (spec 10.5).
 */
export const VERIFIER_TARGETS = ['noir-recursive', 'evm'] as const;
export type VerifierTarget = (typeof VERIFIER_TARGETS)[number];

export function assertVerifierTarget(t: unknown): VerifierTarget {
  if (!VERIFIER_TARGETS.includes(t as VerifierTarget)) throw new Error(`unsupported verifier target ${String(t)}`);
  return t as VerifierTarget;
}

/**
 * The verification keys every verifier must pin. `bbHash` is Barretenberg's own key hash, the
 * value in packages/zk-circuit/fixtures/vk_hashes.txt; `sha256` is the hash of the key file in
 * circuit/vk. A different key means a different circuit.
 */
export const PINNED_VERIFICATION_KEYS: Readonly<Record<VerifierTarget, { readonly bbHash: string; readonly sha256: string }>> = {
  'noir-recursive': {
    bbHash: '0x15bd93c9bb5f2c9bfe73268360c1a69892eb13777e084bdc282d2125fb6cb3de',
    sha256: 'a7d5847b18c780a5e1cc5d31e85158d27e7215490c6f824c7d72c80491979d8b',
  },
  evm: {
    bbHash: '0x0ada696cfd9ba778ed3c2b4d1cb79a4efc0e9a389f2561cd86d6f5b1eba9557b',
    sha256: '49ef4186d6f6d2769d1b8bfce7c37a81dcda5aaebc11db0a7e462f6e9d27c5f6',
  },
};

/** Barretenberg proof settings for a target. Zero knowledge is always on. */
export function proofSettings(target: VerifierTarget) {
  return {
    ipaAccumulation: false,
    oracleHashType: assertVerifierTarget(target) === 'evm' ? 'keccak' : 'poseidon2',
    disableZk: false,
    optimizedSolidityVerifier: false,
  } as const;
}

const circuitDir = new URL('../circuit/', import.meta.url);
let compiled: CompiledCircuit | undefined;

/** The compiled circuit (nargo 1.0.0). */
export function loadCircuit(): CompiledCircuit {
  compiled ??= JSON.parse(readFileSync(new URL('proof_of_intent.json', circuitDir), 'utf8')) as CompiledCircuit;
  return compiled;
}

/** The pinned verification key for a target. Throws if the file does not match its pin. */
export function loadVerificationKey(target: VerifierTarget): Uint8Array {
  const bytes = readFileSync(new URL(`vk/${assertVerifierTarget(target)}.vk`, circuitDir));
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (digest !== PINNED_VERIFICATION_KEYS[target].sha256) {
    throw new Error(`circuit/vk/${target}.vk does not match its pinned hash`);
  }
  return new Uint8Array(bytes);
}

/** Every input of the circuit, typed. */
export interface CircuitInputs {
  readonly policyCommitment: bigint;
  /** u64 Unix seconds. */
  readonly currentTimestamp: bigint;
  readonly actionBinding: bigint;
  readonly policy: PolicyFields;
  readonly action: Action;
  readonly leafIndex: number;
  readonly merklePath: readonly bigint[];
}

export type PublicInputs = readonly [policyCommitment: bigint, currentTimestamp: bigint, actionBinding: bigint];

/** The three public inputs, in circuit order (spec 4.1). */
export function publicInputsOf(inputs: CircuitInputs): PublicInputs {
  return [inputs.policyCommitment, inputs.currentTimestamp, inputs.actionBinding];
}

const dec = (x: bigint, bits: 8 | 32 | 64 | 128, name: string) => assertUint(x, bits, name).toString(10);
const fld = (x: bigint, name: string) => fieldToHex(assertField(x, name));

/**
 * The noir_js input map (spec 4.3): integers as decimal strings, fields as 0x hex strings, never
 * JavaScript numbers.
 */
export function toInputMap(inputs: CircuitInputs): InputMap {
  if (inputs.merklePath.length !== TREE_DEPTH) throw new Error(`merkle_path has ${TREE_DEPTH} entries`);
  return {
    policy_commitment: fld(inputs.policyCommitment, 'policy_commitment'),
    current_timestamp: dec(inputs.currentTimestamp, 64, 'current_timestamp'),
    action_binding: fld(inputs.actionBinding, 'action_binding'),
    policy: {
      max_amount: dec(inputs.policy.maxAmount, 128, 'max_amount'),
      allowlist_root: fld(inputs.policy.allowlistRoot, 'allowlist_root'),
      scope_mask: dec(inputs.policy.scopeMask, 64, 'scope_mask'),
      expiry: dec(inputs.policy.expiry, 64, 'expiry'),
      salt: fld(inputs.policy.salt, 'salt'),
    },
    action: {
      tool_id: fld(inputs.action.toolId, 'tool_id'),
      scope_index: dec(BigInt(inputs.action.scopeIndex), 8, 'scope_index'),
      amount: dec(inputs.action.amount, 128, 'amount'),
      recipient: fld(inputs.action.recipient, 'recipient'),
      nonce: fld(inputs.action.nonce, 'nonce'),
    },
    leaf_index: dec(BigInt(inputs.leafIndex), 32, 'leaf_index'),
    merkle_path: inputs.merklePath.map((x, i) => fld(x, `merkle_path[${i}]`)),
  };
}

/** The assertion messages of the circuit (spec section 6), by constraint ID. */
export const CIRCUIT_ASSERTIONS = {
  C1a: 'policy salt must be non-zero',
  C1b: 'policy commitment mismatch',
  C2a: 'leaf index out of range',
  C2b: 'recipient not in allowlist',
  C3a: 'amount must be non-zero',
  C3b: 'amount exceeds policy limit',
  C4a: 'scope index out of range',
  C4b: 'scope not granted by policy',
  C5: 'policy expired',
  C6: 'action binding mismatch',
} as const;
export type CircuitAssertion = (typeof CIRCUIT_ASSERTIONS)[keyof typeof CIRCUIT_ASSERTIONS];
