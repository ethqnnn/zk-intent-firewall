/**
 * How a proof travels with a tool call: an object under one key of the MCP request's
 * `params._meta` (spec 10.2 step 6). It carries the proof, the timestamp, the nonce and which
 * registered commitment to check against, and never the policy or the action binding: the verifier
 * rebuilds the binding from the call it executes.
 */
import { type VerifierTarget, VERIFIER_TARGETS } from './circuit.js';
import { fieldToHex, parseField, parseUint } from './crypto/field.js';

/** `_meta` key of the envelope. */
export const INTENT_META_KEY = 'zkif/proof-of-intent';

/** Upper bound on an encoded proof. Real proofs are 14,656 (noir-recursive) or 7,616 (evm) bytes. */
export const MAX_PROOF_BYTES = 32 * 1024;

export interface IntentEnvelope {
  readonly target: VerifierTarget;
  readonly policyCommitment: bigint;
  readonly currentTimestamp: bigint;
  readonly nonce: bigint;
  readonly proof: Uint8Array;
}

export interface IntentEnvelopeWire {
  readonly v: 1;
  readonly target: VerifierTarget;
  /** 0x hex, 64 digits. */
  readonly policy_commitment: string;
  /** Unix seconds, decimal. */
  readonly current_timestamp: string;
  /** 0x hex, 64 digits. */
  readonly nonce: string;
  /** Standard base64. */
  readonly proof: string;
}

export class EnvelopeError extends Error {
  override readonly name = 'EnvelopeError';
}

export function encodeEnvelope(e: IntentEnvelope): IntentEnvelopeWire {
  return {
    v: 1,
    target: e.target,
    policy_commitment: fieldToHex(e.policyCommitment),
    current_timestamp: parseUint(e.currentTimestamp, 64, 'current_timestamp').toString(10),
    nonce: fieldToHex(e.nonce),
    proof: Buffer.from(e.proof).toString('base64'),
  };
}

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

/** Strict decoding. Anything unexpected is an EnvelopeError. */
export function decodeEnvelope(wire: unknown): IntentEnvelope {
  if (typeof wire !== 'object' || wire === null || Array.isArray(wire)) throw new EnvelopeError('envelope is not an object');
  const w = wire as Record<string, unknown>;
  const keys = Object.keys(w).sort().join(',');
  if (keys !== 'current_timestamp,nonce,policy_commitment,proof,target,v') throw new EnvelopeError('envelope has unexpected fields');
  if (w.v !== 1) throw new EnvelopeError('unsupported envelope version');
  if (!VERIFIER_TARGETS.includes(w.target as VerifierTarget)) throw new EnvelopeError('unsupported verifier target');
  if (typeof w.proof !== 'string' || w.proof.length > Math.ceil(MAX_PROOF_BYTES / 3) * 4 || w.proof.length % 4 !== 0 || !BASE64.test(w.proof)) {
    throw new EnvelopeError('proof is not base64 of an acceptable size');
  }
  if (typeof w.current_timestamp !== 'string') throw new EnvelopeError('current_timestamp must be a decimal string');
  try {
    return {
      target: w.target as VerifierTarget,
      policyCommitment: parseField(w.policy_commitment, 'policy_commitment'),
      currentTimestamp: parseUint(w.current_timestamp, 64, 'current_timestamp'),
      nonce: parseField(w.nonce, 'nonce'),
      proof: new Uint8Array(Buffer.from(w.proof, 'base64')),
    };
  } catch (e) {
    throw new EnvelopeError(e instanceof Error ? e.message : String(e));
  }
}
