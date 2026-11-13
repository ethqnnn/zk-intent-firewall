/**
 * The verifier checklist of spec 10.3, for the party that executes the tool call. It is a
 * different party from the prover: it trusts nothing in the request except the nonce, the proof,
 * which registered commitment to check, and a timestamp it checks against its own clock.
 *
 *   1. The commitment is in its own registry and not revoked.
 *   2. The timestamp is within a small window of its own clock.
 *   3. tool_id, scope_index, amount and recipient come from the call and its own catalog.
 *   4. It recomputes action_binding.
 *   5. It refuses a (commitment, binding) pair it has seen.
 *   6. It verifies the proof against the pinned key with [commitment, timestamp, binding].
 *   7. The caller executes exactly the call that was bound.
 */
import type { VerifierTarget } from '../circuit.js';
import { getHasher, type ProtocolHasher } from '../crypto/hash.js';
import type { Action } from '../crypto/types.js';
import { decodeEnvelope, EnvelopeError, INTENT_META_KEY } from '../envelope.js';
import { ActionMappingError, type ToolArguments, type ToolCatalog } from '../tools.js';
import { ProofVerifier } from './proof-verifier.js';
import { type PolicyRegistry, unixNow } from './registry.js';
import { InMemoryReplayStore, replayKey, type ReplayStore } from './replay.js';

export type RejectionReason =
  | 'missing_proof'
  | 'malformed_envelope'
  | 'target_not_accepted'
  | 'unknown_tool'
  | 'malformed_arguments'
  | 'commitment_unknown'
  | 'commitment_revoked'
  | 'timestamp_stale'
  | 'timestamp_in_future'
  | 'replayed'
  | 'invalid_proof';

export type VerificationResult =
  | {
      readonly ok: true;
      /** The action that was proven, rebuilt from the call. Execute exactly this. */
      readonly action: Action;
      readonly policyCommitment: bigint;
      readonly currentTimestamp: bigint;
      readonly actionBinding: bigint;
    }
  | { readonly ok: false; readonly reason: RejectionReason; readonly detail?: string };

export interface FreshnessWindow {
  /** Oldest accepted timestamp, in seconds before the verifier's clock. Default 60. */
  readonly maxAgeSeconds: bigint;
  /** Newest accepted timestamp, in seconds after the verifier's clock. Default 5. */
  readonly maxFutureSkewSeconds: bigint;
}

export const DEFAULT_FRESHNESS: FreshnessWindow = { maxAgeSeconds: 60n, maxFutureSkewSeconds: 5n };

export interface IntentVerifierOptions {
  /** This server's own catalog, built with its own server identity. */
  readonly catalog: ToolCatalog;
  readonly registry: PolicyRegistry;
  /** Default: a new in-memory store. Use a shared store when several processes verify. */
  readonly replayStore?: ReplayStore;
  /** Default: a new ProofVerifier. */
  readonly proofVerifier?: ProofVerifier;
  readonly clock?: () => bigint;
  readonly freshness?: FreshnessWindow;
  /** Default: both zero-knowledge targets. */
  readonly acceptedTargets?: readonly VerifierTarget[];
}

export class IntentVerifier {
  readonly #o: Required<Omit<IntentVerifierOptions, 'proofVerifier'>>;
  readonly #proofs: ProofVerifier;
  readonly #hasher: ProtocolHasher;
  readonly #ownsProofVerifier: boolean;

  private constructor(o: IntentVerifierOptions, proofs: ProofVerifier, hasher: ProtocolHasher, owns: boolean) {
    this.#o = {
      catalog: o.catalog,
      registry: o.registry,
      replayStore: o.replayStore ?? new InMemoryReplayStore(),
      clock: o.clock ?? unixNow,
      freshness: o.freshness ?? DEFAULT_FRESHNESS,
      acceptedTargets: o.acceptedTargets ?? ['noir-recursive', 'evm'],
    };
    if (this.#o.freshness.maxAgeSeconds < 0n || this.#o.freshness.maxFutureSkewSeconds < 0n) throw new Error('freshness window must be non-negative');
    this.#proofs = proofs;
    this.#hasher = hasher;
    this.#ownsProofVerifier = owns;
  }

  static async create(options: IntentVerifierOptions): Promise<IntentVerifier> {
    const owns = options.proofVerifier === undefined;
    const [proofs, hasher] = await Promise.all([options.proofVerifier ?? ProofVerifier.create(), getHasher()]);
    return new IntentVerifier(options, proofs, hasher, owns);
  }

  get catalog(): ToolCatalog {
    return this.#o.catalog;
  }

  /**
   * Runs the checklist for a call to `toolName` with `args`, carrying `meta` (the request's
   * `params._meta`). Only an `ok: true` result may be executed.
   */
  async verify(toolName: string, args: ToolArguments, meta: unknown): Promise<VerificationResult> {
    const raw = typeof meta === 'object' && meta !== null ? (meta as Record<string, unknown>)[INTENT_META_KEY] : undefined;
    if (raw === undefined) return reject('missing_proof');
    let envelope;
    try {
      envelope = decodeEnvelope(raw);
    } catch (e) {
      return reject('malformed_envelope', e instanceof EnvelopeError ? e.message : undefined);
    }
    if (!this.#o.acceptedTargets.includes(envelope.target)) return reject('target_not_accepted');

    // 1. Registry.
    const status = await this.#o.registry.status(envelope.policyCommitment);
    if (status === 'unknown') return reject('commitment_unknown');
    if (status === 'revoked') return reject('commitment_revoked');

    // 2. Freshness, against this verifier's clock.
    const now = this.#o.clock();
    const { maxAgeSeconds, maxFutureSkewSeconds } = this.#o.freshness;
    if (envelope.currentTimestamp + maxAgeSeconds < now) return reject('timestamp_stale');
    if (envelope.currentTimestamp > now + maxFutureSkewSeconds) return reject('timestamp_in_future');

    // 3. The action, from the call and this verifier's catalog. Only the nonce is the prover's.
    if (!this.#o.catalog.has(toolName)) return reject('unknown_tool');
    let action: Action;
    try {
      action = { ...this.#o.catalog.resolve(toolName, args), nonce: envelope.nonce };
    } catch (e) {
      return reject('malformed_arguments', e instanceof ActionMappingError ? e.message : undefined);
    }

    // 4. Binding.
    const actionBinding = this.#hasher.actionBinding(action);

    // 5. Replay, cheap check first; the atomic claim follows a valid proof so that an invalid
    //    proof cannot burn a binding.
    const key = replayKey(envelope.policyCommitment, actionBinding);
    if (await this.#o.replayStore.has(key, now)) return reject('replayed');

    // 6. Proof, against the pinned key, with public inputs built here.
    const valid = await this.#proofs.verify(envelope.target, envelope.proof, [envelope.policyCommitment, envelope.currentTimestamp, actionBinding]);
    if (!valid) return reject('invalid_proof');

    if (!(await this.#o.replayStore.claim(key, envelope.currentTimestamp + maxAgeSeconds, now))) return reject('replayed');

    return { ok: true, action, policyCommitment: envelope.policyCommitment, currentTimestamp: envelope.currentTimestamp, actionBinding };
  }

  async destroy(): Promise<void> {
    if (this.#ownsProofVerifier) await this.#proofs.destroy();
  }
}

function reject(reason: RejectionReason, detail?: string): VerificationResult {
  return detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };
}
