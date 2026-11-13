/**
 * The passkey approval statement (docs/circuit-spec.md D11, L3 and 10.5).
 *
 * A policy commitment becomes active at a verifier only when the policy owner's passkey has signed
 * this statement. WebAuthn signs `authenticatorData || SHA-256(clientDataJSON)`, and clientDataJSON
 * carries the challenge, so the challenge is how a statement gets signed:
 *
 *   challenge = base64url( SHA-256( UTF-8( statement text ) ) )
 *
 * The statement names, one per line:
 *
 *   zkif.policy-approval.v1                 protocol label (10.5: an approval cannot be reinterpreted)
 *   action: register | revoke               so an approval can never be replayed as a revocation, or back
 *   policy_commitment: 0x…                  the commitment, 64 lowercase hex digits
 *   vk_hash.<target>: 0x…                   Barretenberg hash of every verification key the verifier
 *                                           accepts, sorted by target (10.5: bound to this circuit)
 *   nonce: …                                single-use value the verifier issued, base64url of 32 bytes
 *
 * The verifier never takes the challenge from the request: it rebuilds this text from its own
 * label, its own pinned keys, the nonce it issued and the commitment the request names, and checks
 * that the passkey signed exactly that. The dashboard rebuilds it too, before asking the passkey to
 * sign, so a relaying server cannot get a different statement signed than the one on screen.
 *
 * This module runs in the browser and in Node: it uses only WebCrypto and plain strings.
 */

export const APPROVAL_LABEL = 'zkif.policy-approval.v1';

export const APPROVAL_ACTIONS = ['register', 'revoke'] as const;
export type ApprovalAction = (typeof APPROVAL_ACTIONS)[number];

/**
 * Barretenberg's hash of each pinned verification key, as in packages/zk-circuit/fixtures/vk_hashes.txt
 * and PINNED_VERIFICATION_KEYS of packages/mcp-firewall. Copied here because that module reads files
 * and cannot be bundled for the browser; test/approval.test.ts checks that they are equal.
 */
export const PINNED_VK_HASHES: Readonly<Record<string, string>> = Object.freeze({
  evm: '0x0ada696cfd9ba778ed3c2b4d1cb79a4efc0e9a389f2561cd86d6f5b1eba9557b',
  'noir-recursive': '0x15bd93c9bb5f2c9bfe73268360c1a69892eb13777e084bdc282d2125fb6cb3de',
});

export interface ApprovalStatement {
  readonly label: string;
  readonly action: ApprovalAction;
  /** 0x followed by 64 lowercase hex digits. */
  readonly policyCommitment: string;
  /** Verifier target to key hash (0x followed by 64 lowercase hex digits). */
  readonly vkHashes: Readonly<Record<string, string>>;
  /** base64url (no padding) of 32 random bytes. */
  readonly nonce: string;
}

export class StatementError extends Error {
  override readonly name = 'StatementError';
}

const LABEL = /^[a-z0-9][a-z0-9.-]{0,63}$/;
const HEX32 = /^0x[0-9a-f]{64}$/;
const TARGET = /^[a-z0-9][a-z0-9-]{0,31}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;

/** The canonical text of a statement. Throws StatementError for anything off-format. */
export function encodeStatement(s: ApprovalStatement): string {
  if (typeof s.label !== 'string' || !LABEL.test(s.label)) throw new StatementError('label is not a protocol label');
  if (!APPROVAL_ACTIONS.includes(s.action)) throw new StatementError('action must be register or revoke');
  if (typeof s.policyCommitment !== 'string' || !HEX32.test(s.policyCommitment)) {
    throw new StatementError('policy_commitment must be 0x followed by 64 lowercase hex digits');
  }
  const targets = Object.keys(s.vkHashes).sort();
  if (targets.length === 0) throw new StatementError('at least one verification key hash is required');
  for (const t of targets) {
    if (!TARGET.test(t)) throw new StatementError(`verifier target ${t} is not well-formed`);
    const h = s.vkHashes[t];
    if (typeof h !== 'string' || !HEX32.test(h)) throw new StatementError(`vk_hash.${t} must be 0x followed by 64 lowercase hex digits`);
  }
  if (typeof s.nonce !== 'string' || !NONCE.test(s.nonce)) throw new StatementError('nonce must be base64url of 32 bytes');
  const lines = [
    s.label,
    `action: ${s.action}`,
    `policy_commitment: ${s.policyCommitment}`,
    ...targets.map((t) => `vk_hash.${t}: ${s.vkHashes[t]}`),
    `nonce: ${s.nonce}`,
  ];
  return lines.join('\n') + '\n';
}

/** `base64url(SHA-256(UTF-8(text)))`, the WebAuthn challenge for a statement text. */
export async function challengeForText(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return base64url(new Uint8Array(digest));
}

/** The WebAuthn challenge that signs `s`. */
export async function statementChallenge(s: ApprovalStatement): Promise<string> {
  return challengeForText(encodeStatement(s));
}

/** A fresh nonce: base64url of 32 bytes from the platform CSPRNG. */
export function newApprovalNonce(): string {
  return base64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

export function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
