/**
 * The verifier's registry, gated by the policy owner's passkey (spec D11, L3, 10.3 step 1, 10.5).
 *
 * packages/mcp-firewall's InMemoryPolicyRegistry.register trusts its caller. This class is that
 * caller: it holds the registry privately and changes it only after a WebAuthn assertion verifies,
 * against the owner's enrolled credential, over the approval statement of shared/approval.ts that
 * this verifier rebuilds from its own state:
 *
 *   - its own protocol label and the hashes of the verification keys it pins;
 *   - a nonce it issued, for this action and this commitment, unexpired, and never used before;
 *   - the action (register or revoke) and the commitment the request names.
 *
 * The cryptographic check is @simplewebauthn/server's verifyAuthenticationResponse: client data
 * type `webauthn.get`, challenge, origin, RP ID hash, user presence and user verification flags,
 * signature counter, and the signature over authenticatorData || SHA-256(clientDataJSON) with the
 * enrolled public key. That library does not compare the response's credential ID with the
 * credential it is given, and it reports a bad signature as `verified: false` rather than an
 * exception; both are checked here.
 *
 * Revocation needs the same passkey and is final: a revoked commitment never becomes active again.
 */
import {
  type AuthenticationResponseJSON,
  generateRegistrationOptions,
  type PublicKeyCredentialCreationOptionsJSON,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import {
  type CommitmentStatus,
  fieldToHex,
  InMemoryPolicyRegistry,
  parseField,
  PINNED_VERIFICATION_KEYS,
  type PolicyRegistry,
  type RegistrationRecord,
  unixNow,
  type VerifierTarget,
  VERIFIER_TARGETS,
} from '@zk-intent-firewall/mcp-firewall';
import type { ApprovalRejection, ApprovalRequest, ApprovalResult, ChallengeResponse, EnrollmentResult } from '../../shared/api.ts';
import { APPROVAL_ACTIONS, APPROVAL_LABEL, type ApprovalAction, type ApprovalStatement, encodeStatement, newApprovalNonce, statementChallenge } from '../../shared/approval.ts';

/** ES256 (P-256) first, RS256 for platform authenticators that only offer RSA. */
export const SUPPORTED_ALGORITHMS = [-7, -257];

export interface PasskeyRegistryOptions {
  /** WebAuthn relying party ID, for example `localhost`. */
  readonly rpId: string;
  readonly rpName: string;
  /** Origins the dashboard is served from, for example `http://localhost:5173`. */
  readonly expectedOrigins: readonly string[];
  /** Default: both zero-knowledge targets, as IntentVerifier accepts by default. */
  readonly acceptedTargets?: readonly VerifierTarget[];
  readonly clock?: () => bigint;
  /** Lifetime of an approval nonce or an enrollment challenge. Default 300 seconds. */
  readonly challengeTtlSeconds?: bigint;
}

interface IssuedNonce {
  readonly action: ApprovalAction;
  readonly commitment: string;
  readonly expiresAt: bigint;
}

const MAX_OUTSTANDING_NONCES = 64;

export interface RegistryRecordView {
  readonly policyCommitment: string;
  readonly status: CommitmentStatus;
  readonly registeredAt?: string;
  readonly revokedAt?: string;
}

export class PasskeyPolicyRegistry implements PolicyRegistry {
  readonly #inner: InMemoryPolicyRegistry;
  readonly #o: Required<Omit<PasskeyRegistryOptions, 'acceptedTargets'>> & { acceptedTargets: readonly VerifierTarget[] };
  readonly #nonces = new Map<string, IssuedNonce>();
  #owner: WebAuthnCredential | undefined;
  #enrollment: { readonly challenge: string; readonly expiresAt: bigint } | undefined;

  constructor(options: PasskeyRegistryOptions) {
    if (options.expectedOrigins.length === 0) throw new Error('at least one expected origin is required');
    this.#o = {
      rpId: options.rpId,
      rpName: options.rpName,
      expectedOrigins: [...options.expectedOrigins],
      acceptedTargets: options.acceptedTargets ?? VERIFIER_TARGETS,
      clock: options.clock ?? unixNow,
      challengeTtlSeconds: options.challengeTtlSeconds ?? 300n,
    };
    this.#inner = new InMemoryPolicyRegistry({ clock: this.#o.clock });
  }

  // -- PolicyRegistry: what IntentVerifier consults on every call --------------------------------

  status(commitment: bigint): CommitmentStatus {
    return this.#inner.status(commitment);
  }

  get rpId(): string {
    return this.#o.rpId;
  }

  get ownerCredentialId(): string | undefined {
    return this.#owner?.id;
  }

  /** Target to Barretenberg key hash, for every target this verifier accepts. */
  vkHashes(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const t of this.#o.acceptedTargets) out[t] = PINNED_VERIFICATION_KEYS[t].bbHash;
    return out;
  }

  records(commitments: readonly string[]): RegistryRecordView[] {
    return commitments.flatMap((hex) => {
      let c: bigint;
      try {
        c = parseField(hex);
      } catch {
        return [];
      }
      const r: RegistrationRecord | undefined = this.#inner.get(c);
      return [
        {
          policyCommitment: fieldToHex(c),
          status: this.#inner.status(c),
          ...(r ? { registeredAt: r.registeredAt.toString() } : {}),
          ...(r?.revokedAt !== undefined ? { revokedAt: r.revokedAt.toString() } : {}),
        },
      ];
    });
  }

  // -- Enrollment of the owner's passkey ----------------------------------------------------------

  /**
   * Options for navigator.credentials.create. Enrollment is open only while no owner is enrolled
   * (trust on first use); the host additionally requires its session token before relaying.
   */
  async enrollmentOptions(): Promise<PublicKeyCredentialCreationOptionsJSON> {
    if (this.#owner) throw new Error('a policy owner passkey is already enrolled');
    const options = await generateRegistrationOptions({
      rpName: this.#o.rpName,
      rpID: this.#o.rpId,
      userName: 'policy-owner',
      userDisplayName: 'Policy owner',
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
      timeout: 120_000,
    });
    this.#enrollment = { challenge: options.challenge, expiresAt: this.#o.clock() + this.#o.challengeTtlSeconds };
    return options;
  }

  async completeEnrollment(response: unknown): Promise<EnrollmentResult> {
    if (this.#owner) return { ok: false, reason: 'owner_already_enrolled' };
    const pending = this.#enrollment;
    this.#enrollment = undefined;
    if (!pending) return { ok: false, reason: 'no_enrollment_in_progress' };
    if (pending.expiresAt < this.#o.clock()) return { ok: false, reason: 'enrollment_expired' };
    const parsed = parseRegistrationResponse(response);
    if (!parsed) return { ok: false, reason: 'malformed_request' };
    try {
      const v = await verifyRegistrationResponse({
        response: parsed,
        expectedChallenge: pending.challenge,
        expectedOrigin: [...this.#o.expectedOrigins],
        expectedRPID: this.#o.rpId,
        requireUserVerification: true,
        supportedAlgorithmIDs: SUPPORTED_ALGORITHMS,
      });
      if (!v.verified || !v.registrationInfo || !v.registrationInfo.userVerified) return { ok: false, reason: 'attestation_invalid' };
      this.#owner = { ...v.registrationInfo.credential };
      return { ok: true, credentialId: this.#owner.id };
    } catch (e) {
      return { ok: false, reason: 'attestation_invalid', detail: e instanceof Error ? e.message : String(e) };
    }
  }

  // -- Approvals ------------------------------------------------------------------------------------

  /**
   * Issues a single-use nonce for `action` on `policyCommitment`, and the statement the passkey must
   * sign. Throws for a malformed commitment, with no owner enrolled, or to register a revoked one.
   */
  async issueApproval(action: unknown, policyCommitment: unknown): Promise<ChallengeResponse> {
    if (!APPROVAL_ACTIONS.includes(action as ApprovalAction)) throw new Error('action must be register or revoke');
    const commitment = fieldToHex(parseField(policyCommitment, 'policyCommitment'));
    if (!this.#owner) throw new Error('no policy owner passkey is enrolled');
    if (action === 'register' && this.#inner.status(parseField(commitment)) === 'revoked') {
      throw new Error('this policy commitment was revoked and cannot be registered again');
    }
    const now = this.#o.clock();
    for (const [k, v] of this.#nonces) if (v.expiresAt < now) this.#nonces.delete(k);
    if (this.#nonces.size >= MAX_OUTSTANDING_NONCES) throw new Error('too many outstanding approval requests');

    const nonce = newApprovalNonce();
    this.#nonces.set(nonce, { action: action as ApprovalAction, commitment, expiresAt: now + this.#o.challengeTtlSeconds });
    const statement: ApprovalStatement = { label: APPROVAL_LABEL, action: action as ApprovalAction, policyCommitment: commitment, vkHashes: this.vkHashes(), nonce };
    return {
      statement,
      statementText: encodeStatement(statement),
      challenge: await statementChallenge(statement),
      rpId: this.#o.rpId,
      allowCredentials: [{ id: this.#owner.id, type: 'public-key', ...(this.#owner.transports ? { transports: [...this.#owner.transports] } : {}) }],
      timeoutMs: Number(this.#o.challengeTtlSeconds) * 1000,
    };
  }

  /** Activates a commitment after verifying the owner's approval of it. */
  async approveRegistration(request: ApprovalRequest): Promise<ApprovalResult> {
    const v = await this.#verifyApproval('register', request);
    if (!v.ok) return v;
    if (this.#inner.status(v.commitment) === 'revoked') return reject('commitment_revoked');
    this.#inner.register(v.commitment, { label: 'approved by policy owner passkey' });
    return { ok: true, status: this.#inner.status(v.commitment) };
  }

  /** Revokes a commitment after verifying the owner's approval of the revocation. Final. */
  async approveRevocation(request: ApprovalRequest): Promise<ApprovalResult> {
    const v = await this.#verifyApproval('revoke', request);
    if (!v.ok) return v;
    this.#inner.revoke(v.commitment, 'revoked by policy owner passkey');
    return { ok: true, status: this.#inner.status(v.commitment) };
  }

  async #verifyApproval(action: ApprovalAction, request: ApprovalRequest): Promise<{ ok: true; commitment: bigint } | Extract<ApprovalResult, { ok: false }>> {
    if (typeof request !== 'object' || request === null) return reject('malformed_request');
    let commitment: bigint;
    try {
      commitment = parseField(request.policyCommitment, 'policyCommitment');
    } catch {
      return reject('malformed_request', 'policyCommitment is not a field element');
    }
    const commitmentHex = fieldToHex(commitment);
    const owner = this.#owner;
    if (!owner) return reject('no_owner_enrolled');

    // The nonce is consumed by the first attempt, whatever its outcome.
    if (typeof request.nonce !== 'string') return reject('malformed_request', 'nonce is missing');
    const issued = this.#nonces.get(request.nonce);
    this.#nonces.delete(request.nonce);
    if (!issued) return reject('unknown_nonce');
    if (issued.expiresAt < this.#o.clock()) return reject('nonce_expired');
    if (issued.action !== action || issued.commitment !== commitmentHex) return reject('nonce_mismatch');

    const response = parseAuthenticationResponse(request.response);
    if (!response) return reject('malformed_request', 'response is not a WebAuthn assertion');
    if (response.id !== owner.id) return reject('unknown_credential');

    // The challenge is rebuilt here from this verifier's own state, never read from the request.
    const statement: ApprovalStatement = { label: APPROVAL_LABEL, action, policyCommitment: commitmentHex, vkHashes: this.vkHashes(), nonce: request.nonce };
    const expectedChallenge = await statementChallenge(statement);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: [...this.#o.expectedOrigins],
        expectedRPID: this.#o.rpId,
        credential: owner,
        requireUserVerification: true,
      });
    } catch (e) {
      return reject('signature_invalid', e instanceof Error ? e.message : String(e));
    }
    if (verification.verified !== true || verification.authenticationInfo.userVerified !== true) return reject('signature_invalid');
    this.#owner = { ...owner, counter: verification.authenticationInfo.newCounter };
    return { ok: true, commitment };
  }
}

function reject(reason: ApprovalRejection, detail?: string): Extract<ApprovalResult, { ok: false }> {
  return detail === undefined ? { ok: false, reason } : { ok: false, reason, detail };
}

const isStr = (x: unknown): x is string => typeof x === 'string' && x.length > 0;

/** Shape check of an AuthenticationResponseJSON. Content is checked by the verification itself. */
export function parseAuthenticationResponse(x: unknown): AuthenticationResponseJSON | undefined {
  if (typeof x !== 'object' || x === null) return undefined;
  const r = x as Record<string, unknown>;
  const resp = r['response'];
  if (!isStr(r['id']) || !isStr(r['rawId']) || r['type'] !== 'public-key' || typeof resp !== 'object' || resp === null) return undefined;
  const a = resp as Record<string, unknown>;
  if (!isStr(a['clientDataJSON']) || !isStr(a['authenticatorData']) || !isStr(a['signature'])) return undefined;
  if (a['userHandle'] !== undefined && typeof a['userHandle'] !== 'string') return undefined;
  return {
    id: r['id'],
    rawId: r['rawId'],
    type: 'public-key',
    response: {
      clientDataJSON: a['clientDataJSON'],
      authenticatorData: a['authenticatorData'],
      signature: a['signature'],
      ...(typeof a['userHandle'] === 'string' ? { userHandle: a['userHandle'] } : {}),
    },
    clientExtensionResults: {},
  };
}

/** Shape check of a RegistrationResponseJSON. */
export function parseRegistrationResponse(x: unknown): RegistrationResponseJSON | undefined {
  if (typeof x !== 'object' || x === null) return undefined;
  const r = x as Record<string, unknown>;
  const resp = r['response'];
  if (!isStr(r['id']) || !isStr(r['rawId']) || r['type'] !== 'public-key' || typeof resp !== 'object' || resp === null) return undefined;
  const a = resp as Record<string, unknown>;
  if (!isStr(a['clientDataJSON']) || !isStr(a['attestationObject'])) return undefined;
  const transports = Array.isArray(a['transports']) ? (a['transports'] as unknown[]).filter((t): t is string => typeof t === 'string') : undefined;
  return {
    id: r['id'],
    rawId: r['rawId'],
    type: 'public-key',
    response: {
      clientDataJSON: a['clientDataJSON'],
      attestationObject: a['attestationObject'],
      ...(transports ? { transports: transports as NonNullable<RegistrationResponseJSON['response']['transports']> } : {}),
    },
    clientExtensionResults: {},
  };
}
