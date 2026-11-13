/**
 * The passkey gate in front of the verifier's registry (spec D11, L3, 10.5). Every test starts
 * from a genuine assertion by the enrolled software authenticator (real P-256 ECDSA over real
 * authenticatorData and clientDataJSON) and breaks exactly one thing. Each must leave the registry
 * unchanged.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import type { ApprovalRequest } from '../src/shared/api.ts';
import { APPROVAL_LABEL, type ApprovalAction, type ApprovalStatement, PINNED_VK_HASHES, statementChallenge } from '../src/shared/approval.ts';
import { AUTHENTICATOR_FLAGS, SoftAuthenticator } from '../src/demo/soft-authenticator.ts';
import { PasskeyPolicyRegistry } from '../src/server/verifier/passkey-registry.ts';

const ORIGIN = 'http://localhost:5173';
const RP_ID = 'localhost';
const C1 = '0x' + '0a'.repeat(32);
const C2 = '0x' + '0b'.repeat(32);
const big = (hex: string) => BigInt(hex);

class Clock {
  now = 1_800_000_000n;
  read = () => this.now;
}

let clock: Clock;
let registry: PasskeyPolicyRegistry;
let owner: SoftAuthenticator;

async function enrol(r: PasskeyPolicyRegistry, a: SoftAuthenticator) {
  const options = await r.enrollmentOptions();
  return r.completeEnrollment(a.createRegistrationResponse(options));
}

/** The statement the owner signs: by default exactly what the verifier issued. */
async function sign(action: ApprovalAction, commitment: string, o: { statement?: Partial<ApprovalStatement>; assertion?: Parameters<SoftAuthenticator['createAssertion']>[1]; by?: SoftAuthenticator } = {}): Promise<ApprovalRequest> {
  const ch = await registry.issueApproval(action, commitment);
  const signed: ApprovalStatement = { ...ch.statement, ...o.statement };
  const challenge = await statementChallenge(signed);
  return { policyCommitment: commitment, nonce: ch.statement.nonce, response: (o.by ?? owner).createAssertion(challenge, o.assertion) };
}

beforeEach(async () => {
  clock = new Clock();
  registry = new PasskeyPolicyRegistry({ rpId: RP_ID, rpName: 'test', expectedOrigins: [ORIGIN], clock: clock.read });
  owner = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
  const r = await enrol(registry, owner);
  expect(r).toEqual({ ok: true, credentialId: owner.credentialId });
});

describe('enrolment', () => {
  it('records the owner credential once; a second enrolment is refused (trust on first use)', async () => {
    expect(registry.ownerCredentialId).toBe(owner.credentialId);
    await expect(registry.enrollmentOptions()).rejects.toThrow(/already enrolled/);
    const intruder = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    expect(await registry.completeEnrollment(intruder.createRegistrationResponse({ challenge: 'x' }))).toMatchObject({ ok: false, reason: 'owner_already_enrolled' });
    expect(registry.ownerCredentialId).toBe(owner.credentialId);
  });

  for (const [name, tweak, reason] of [
    ['a different challenge', { challenge: 'not-the-issued-challenge' }, 'attestation_invalid'],
    ['a foreign origin', { origin: 'https://evil.example' }, 'attestation_invalid'],
    ['a foreign RP ID', { rpId: 'evil.example' }, 'attestation_invalid'],
    ['no user verification', { flags: AUTHENTICATOR_FLAGS.UP | AUTHENTICATOR_FLAGS.AT }, 'attestation_invalid'],
  ] as const) {
    it(`refuses an attestation with ${name}`, async () => {
      const r = new PasskeyPolicyRegistry({ rpId: RP_ID, rpName: 'test', expectedOrigins: [ORIGIN], clock: clock.read });
      const a = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
      const options = await r.enrollmentOptions();
      const challenge = 'challenge' in tweak ? tweak.challenge : options.challenge;
      const res = a.createRegistrationResponse({ challenge }, { ...('origin' in tweak ? { origin: tweak.origin } : {}), ...('rpId' in tweak ? { rpId: tweak.rpId } : {}), ...('flags' in tweak ? { flags: tweak.flags } : {}) });
      expect(await r.completeEnrollment(res)).toMatchObject({ ok: false, reason });
      expect(r.ownerCredentialId).toBeUndefined();
    });
  }

  it('refuses an enrolment that was never started, or has expired', async () => {
    const r = new PasskeyPolicyRegistry({ rpId: RP_ID, rpName: 'test', expectedOrigins: [ORIGIN], clock: clock.read });
    const a = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    expect(await r.completeEnrollment(a.createRegistrationResponse({ challenge: 'x' }))).toMatchObject({ ok: false, reason: 'no_enrollment_in_progress' });
    const options = await r.enrollmentOptions();
    clock.now += 301n;
    expect(await r.completeEnrollment(a.createRegistrationResponse(options))).toMatchObject({ ok: false, reason: 'enrollment_expired' });
  });
});

describe('registration approval', () => {
  it('a valid owner signature over the issued statement activates the commitment', async () => {
    expect(registry.status(big(C1))).toBe('unknown');
    expect(await registry.approveRegistration(await sign('register', C1))).toEqual({ ok: true, status: 'active' });
    expect(registry.status(big(C1))).toBe('active');
  });

  it('the issued statement names the label, the action, the commitment and both pinned keys', async () => {
    const ch = await registry.issueApproval('register', C1);
    expect(ch.statement).toMatchObject({ label: APPROVAL_LABEL, action: 'register', policyCommitment: C1, vkHashes: PINNED_VK_HASHES });
    expect(ch.allowCredentials).toMatchObject([{ id: owner.credentialId, type: 'public-key' }]);
    expect(ch.challenge).toBe(await statementChallenge(ch.statement));
  });

  describe('missing or malformed approval', () => {
    const cases: [string, (r: ApprovalRequest) => unknown][] = [
      ['no response at all', (r) => ({ ...r, response: undefined })],
      ['a response that is not an object', (r) => ({ ...r, response: 'signature' })],
      ['a response without a signature', (r) => ({ ...r, response: { ...(r.response as object), response: { ...((r.response as { response: object }).response), signature: undefined } } })],
      ['a response of the wrong type', (r) => ({ ...r, response: { ...(r.response as object), type: 'password' } })],
      ['no nonce', (r) => ({ ...r, nonce: undefined })],
      ['a commitment that is not a field element', (r) => ({ ...r, policyCommitment: '0x' + 'ff'.repeat(32) })],
      ['a commitment in decimal', (r) => ({ ...r, policyCommitment: '123' })],
      ['nothing', () => null],
    ];
    for (const [name, f] of cases) {
      it(`refuses ${name}`, async () => {
        const r = await registry.approveRegistration(f(await sign('register', C1)) as ApprovalRequest);
        expect(r.ok).toBe(false);
        expect(registry.status(big(C1))).toBe('unknown');
      });
    }

    it('refuses an empty signature, and one that is not DER', async () => {
      const empty = await registry.approveRegistration(await sign('register', C1, { assertion: { tamperSignature: () => new Uint8Array(0) } }));
      expect(empty).toMatchObject({ ok: false, reason: 'malformed_request' });
      const notDer = await registry.approveRegistration(await sign('register', C1, { assertion: { tamperSignature: () => new Uint8Array(70).fill(0x30) } }));
      expect(notDer).toMatchObject({ ok: false, reason: 'signature_invalid' });
      expect(registry.status(big(C1))).toBe('unknown');
    });
  });

  describe('a signature that does not verify', () => {
    const cases: [string, Parameters<SoftAuthenticator['createAssertion']>[1]][] = [
      ['one flipped bit in the signature', { tamperSignature: (s) => Uint8Array.from(s, (b, i) => (i === 10 ? b ^ 1 : b)) }],
      ['signed by a different key', { signingKey: SoftAuthenticator.otherKey() }],
      ['authenticatorData changed after signing (counter)', { tamperAuthData: (d) => Uint8Array.from(d, (b, i) => (i === d.length - 1 ? b ^ 0x40 : b)) }],
      ['clientDataJSON changed after signing', { tamperClientData: (c) => c.replace('"crossOrigin":false', '"crossOrigin":false ') }],
      ['a foreign origin', { origin: 'https://evil.example' }],
      ['a foreign RP ID', { rpId: 'evil.example' }],
      ['a create-type client data', { type: 'webauthn.create' }],
      ['no user verification (UV flag clear)', { flags: AUTHENTICATOR_FLAGS.UP }],
      ['no user presence', { flags: AUTHENTICATOR_FLAGS.UV }],
    ];
    for (const [name, assertion] of cases) {
      it(`refuses ${name}`, async () => {
        const r = await registry.approveRegistration(await sign('register', C1, { assertion }));
        expect(r).toMatchObject({ ok: false, reason: 'signature_invalid' });
        expect(registry.status(big(C1))).toBe('unknown');
      });
    }
  });

  describe('a valid signature over a different statement', () => {
    // The verifier issued a nonce for (register, C2). The owner's passkey signed a statement with
    // that nonce but other content: what a dishonest relay would try, showing C1 and registering C2.
    const cases: [string, Partial<ApprovalStatement>][] = [
      ['another commitment', { policyCommitment: C1 }],
      ['another verification key (another circuit)', { vkHashes: { ...PINNED_VK_HASHES, 'noir-recursive': '0x' + '11'.repeat(32) } }],
      ['fewer verification keys', { vkHashes: { evm: PINNED_VK_HASHES['evm']! } }],
      ['another protocol label', { label: 'zkif.policy-approval.v0' }],
      ['another protocol entirely', { label: 'acme.login.v1' }],
      ['another action', { action: 'revoke' }],
      ['another nonce', { nonce: 'Z'.repeat(43) }],
    ];
    for (const [name, statement] of cases) {
      it(`refuses a statement for ${name}`, async () => {
        const r = await registry.approveRegistration(await sign('register', C2, { statement }));
        expect(r).toMatchObject({ ok: false, reason: 'signature_invalid' });
        expect(registry.status(big(C2))).toBe('unknown');
        expect(registry.status(big(C1))).toBe('unknown');
      });
    }

    it('refuses a challenge chosen by the client, even when it is signed correctly', async () => {
      const ch = await registry.issueApproval('register', C2);
      const response = owner.createAssertion('Y2hvc2VuLWJ5LXRoZS1jbGllbnQ');
      expect(await registry.approveRegistration({ policyCommitment: C2, nonce: ch.statement.nonce, response })).toMatchObject({ ok: false, reason: 'signature_invalid' });
      expect(registry.status(big(C2))).toBe('unknown');
    });
  });

  describe('nonces', () => {
    it('an approval is accepted once: a replay of the same signed request is refused', async () => {
      const req = await sign('register', C1);
      expect(await registry.approveRegistration(req)).toMatchObject({ ok: true });
      expect(await registry.approveRegistration(req)).toMatchObject({ ok: false, reason: 'unknown_nonce' });
    });

    it('a failed attempt burns the nonce too', async () => {
      const req = await sign('register', C1);
      expect(await registry.approveRegistration({ ...req, response: owner.createAssertion('wrong') })).toMatchObject({ ok: false });
      expect(await registry.approveRegistration(req)).toMatchObject({ ok: false, reason: 'unknown_nonce' });
      expect(registry.status(big(C1))).toBe('unknown');
    });

    it('refuses a nonce the verifier never issued', async () => {
      const statement: ApprovalStatement = { label: APPROVAL_LABEL, action: 'register', policyCommitment: C1, vkHashes: PINNED_VK_HASHES, nonce: 'Q'.repeat(43) };
      const response = owner.createAssertion(await statementChallenge(statement));
      expect(await registry.approveRegistration({ policyCommitment: C1, nonce: statement.nonce, response })).toMatchObject({ ok: false, reason: 'unknown_nonce' });
      expect(registry.status(big(C1))).toBe('unknown');
    });

    it('refuses an expired nonce', async () => {
      const req = await sign('register', C1);
      clock.now += 301n;
      expect(await registry.approveRegistration(req)).toMatchObject({ ok: false, reason: 'nonce_expired' });
      expect(registry.status(big(C1))).toBe('unknown');
    });

    it('refuses a nonce issued for another commitment or action', async () => {
      const forC2 = await sign('register', C2);
      expect(await registry.approveRegistration({ ...forC2, policyCommitment: C1 })).toMatchObject({ ok: false, reason: 'nonce_mismatch' });
      const forRevoke = await sign('revoke', C1);
      expect(await registry.approveRegistration(forRevoke)).toMatchObject({ ok: false, reason: 'nonce_mismatch' });
      expect(registry.status(big(C1))).toBe('unknown');
    });
  });

  it('refuses an assertion from a credential that is not the enrolled owner', async () => {
    const stranger = new SoftAuthenticator({ origin: ORIGIN, rpId: RP_ID });
    expect(await registry.approveRegistration(await sign('register', C1, { by: stranger }))).toMatchObject({ ok: false, reason: 'unknown_credential' });
    // Claiming the owner's credential ID does not help: the signature is checked with the owner's key.
    expect(await registry.approveRegistration(await sign('register', C1, { by: stranger, assertion: { credentialId: owner.credentialId } }))).toMatchObject({
      ok: false,
      reason: 'signature_invalid',
    });
    expect(registry.status(big(C1))).toBe('unknown');
  });

  it('refuses a signature counter that went backwards (cloned authenticator)', async () => {
    expect(await registry.approveRegistration(await sign('register', C1, { assertion: { counter: 10 } }))).toMatchObject({ ok: true });
    expect(await registry.approveRegistration(await sign('register', C2, { assertion: { counter: 9 } }))).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(registry.status(big(C2))).toBe('unknown');
  });

  it('nothing can be approved before an owner is enrolled', async () => {
    const r = new PasskeyPolicyRegistry({ rpId: RP_ID, rpName: 'test', expectedOrigins: [ORIGIN] });
    await expect(r.issueApproval('register', C1)).rejects.toThrow(/no policy owner/);
    expect(await r.approveRegistration({ policyCommitment: C1, nonce: 'A'.repeat(43), response: {} })).toMatchObject({ ok: false, reason: 'no_owner_enrolled' });
  });
});

describe('revocation approval', () => {
  beforeEach(async () => {
    expect(await registry.approveRegistration(await sign('register', C1))).toMatchObject({ ok: true });
  });

  it('a valid owner signature revokes, and revocation is final', async () => {
    expect(await registry.approveRevocation(await sign('revoke', C1))).toEqual({ ok: true, status: 'revoked' });
    expect(registry.status(big(C1))).toBe('revoked');
    await expect(registry.issueApproval('register', C1)).rejects.toThrow(/revoked/);
  });

  it('a registration approval cannot be replayed as a revocation', async () => {
    const ch = await registry.issueApproval('revoke', C1);
    const signedAsRegister = await statementChallenge({ ...ch.statement, action: 'register' });
    const r = await registry.approveRevocation({ policyCommitment: C1, nonce: ch.statement.nonce, response: owner.createAssertion(signedAsRegister) });
    expect(r).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(registry.status(big(C1))).toBe('active');
  });

  it('a revocation without a valid passkey signature is refused', async () => {
    const forged = await sign('revoke', C1, { assertion: { signingKey: SoftAuthenticator.otherKey() } });
    expect(await registry.approveRevocation(forged)).toMatchObject({ ok: false, reason: 'signature_invalid' });
    expect(await registry.approveRevocation({ policyCommitment: C1, nonce: 'A'.repeat(43), response: undefined })).toMatchObject({ ok: false });
    expect(registry.status(big(C1))).toBe('active');
  });

  it('a revoked commitment cannot be re-registered, even by a valid approval signed before the revocation', async () => {
    // Counters are chosen so that the earlier approval still passes the counter check and only
    // the revocation can stop it.
    const signedEarlier = await sign('register', C1, { assertion: { counter: 100 } });
    expect(await registry.approveRevocation(await sign('revoke', C1, { assertion: { counter: 50 } }))).toMatchObject({ ok: true });
    expect(await registry.approveRegistration(signedEarlier)).toMatchObject({ ok: false, reason: 'commitment_revoked' });
    expect(registry.status(big(C1))).toBe('revoked');
  });
});
