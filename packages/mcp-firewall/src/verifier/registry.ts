/**
 * The verifier's registry of approved policy commitments (spec 10.3 step 1, L2).
 *
 * The circuit has no notion of revocation: a proof for a revoked policy still verifies until the
 * policy expires. Every verifier must therefore look the commitment up at verification time.
 */

export type CommitmentStatus = 'active' | 'revoked' | 'unknown';

export interface PolicyRegistry {
  status(commitment: bigint): CommitmentStatus | Promise<CommitmentStatus>;
}

export interface RegistrationRecord {
  readonly commitment: bigint;
  /** Unix seconds. */
  readonly registeredAt: bigint;
  readonly label?: string;
  readonly revokedAt?: bigint;
  readonly revocationReason?: string;
}

export interface InMemoryPolicyRegistryOptions {
  readonly clock?: () => bigint;
}

/**
 * An in-process registry. `register` trusts its caller to have checked the human approval of the
 * commitment (the passkey signature of spec D11/L3, which Phase 3 provides). Revocation is final:
 * a revoked commitment can never be registered again.
 */
export class InMemoryPolicyRegistry implements PolicyRegistry {
  readonly #records = new Map<bigint, RegistrationRecord>();
  readonly #clock: () => bigint;

  constructor(options: InMemoryPolicyRegistryOptions = {}) {
    this.#clock = options.clock ?? unixNow;
  }

  register(commitment: bigint, meta: { label?: string } = {}): RegistrationRecord {
    const existing = this.#records.get(commitment);
    if (existing?.revokedAt !== undefined) throw new Error('this policy commitment was revoked and cannot be registered again');
    if (existing) return existing;
    const record: RegistrationRecord = {
      commitment,
      registeredAt: this.#clock(),
      ...(meta.label !== undefined ? { label: meta.label } : {}),
    };
    this.#records.set(commitment, record);
    return record;
  }

  revoke(commitment: bigint, reason?: string): RegistrationRecord {
    const existing = this.#records.get(commitment) ?? { commitment, registeredAt: this.#clock() };
    if (existing.revokedAt !== undefined) return existing;
    const record: RegistrationRecord = {
      ...existing,
      revokedAt: this.#clock(),
      ...(reason !== undefined ? { revocationReason: reason } : {}),
    };
    this.#records.set(commitment, record);
    return record;
  }

  get(commitment: bigint): RegistrationRecord | undefined {
    return this.#records.get(commitment);
  }

  status(commitment: bigint): CommitmentStatus {
    const r = this.#records.get(commitment);
    if (r === undefined) return 'unknown';
    return r.revokedAt === undefined ? 'active' : 'revoked';
  }
}

/** The current Unix time in whole seconds. */
export function unixNow(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}
