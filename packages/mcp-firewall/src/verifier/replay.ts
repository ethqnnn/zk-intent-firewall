/**
 * Replay tracking (spec 10.3 step 5, D10, L4). The key is (policy_commitment, action_binding),
 * never the proof bytes: proofs are randomised, so one action has many valid proofs.
 */
import { fieldToHex } from '../crypto/field.js';

export interface ReplayStore {
  /** True if the key was claimed and has not expired at `now`. */
  has(key: string, now: bigint): boolean | Promise<boolean>;
  /**
   * Atomically claims the key until `expiresAt`. False if it is already claimed. Implementations
   * shared between processes must make this a single atomic operation (for example SET NX).
   */
  claim(key: string, expiresAt: bigint, now: bigint): boolean | Promise<boolean>;
}

export function replayKey(policyCommitment: bigint, actionBinding: bigint): string {
  return `${fieldToHex(policyCommitment)}:${fieldToHex(actionBinding)}`;
}

/** A single-process store. Expired entries are dropped as new ones arrive. */
export class InMemoryReplayStore implements ReplayStore {
  readonly #entries = new Map<string, bigint>();

  has(key: string, now: bigint): boolean {
    const exp = this.#entries.get(key);
    return exp !== undefined && exp >= now;
  }

  claim(key: string, expiresAt: bigint, now: bigint): boolean {
    if (this.has(key, now)) return false;
    for (const [k, exp] of this.#entries) if (exp < now) this.#entries.delete(k);
    this.#entries.set(key, expiresAt);
    return true;
  }

  get size(): number {
    return this.#entries.size;
  }
}
