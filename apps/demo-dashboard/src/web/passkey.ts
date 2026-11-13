/**
 * The passkey ceremonies, in the browser. Before asking the passkey to sign an approval, the
 * dashboard rebuilds the statement and its challenge itself and refuses to continue unless they
 * are exactly the approval the user asked for: this action, this commitment, this protocol label
 * and the verification keys this dashboard pins. A relaying server therefore cannot get the
 * passkey to sign anything else.
 */
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type { ChallengeResponse } from '../shared/api.ts';
import { APPROVAL_LABEL, type ApprovalAction, encodeStatement, PINNED_VK_HASHES, statementChallenge } from '../shared/approval.ts';
import type { Api } from './api.ts';

export async function enrolPasskey(api: Api): Promise<string> {
  const optionsJSON = await api.post<Parameters<typeof startRegistration>[0]['optionsJSON']>('/api/passkey/options');
  const response = await startRegistration({ optionsJSON });
  const r = await api.post<{ ok: boolean; credentialId?: string; reason?: string }>('/api/passkey/verify', { response });
  if (!r.ok || !r.credentialId) throw new Error(`the verifier refused the passkey: ${r.reason ?? 'unknown reason'}`);
  return r.credentialId;
}

/** Fetches the statement to sign and checks it locally. Throws if it is not what we asked for. */
export async function requestStatement(api: Api, action: ApprovalAction, policyCommitment: string): Promise<ChallengeResponse> {
  const ch = await api.post<ChallengeResponse>('/api/approvals/challenge', { action, policyCommitment });
  const s = ch.statement;
  const problems: string[] = [];
  if (s.label !== APPROVAL_LABEL) problems.push('protocol label');
  if (s.action !== action) problems.push('action');
  if (s.policyCommitment !== policyCommitment) problems.push('policy commitment');
  const pinned = Object.keys(PINNED_VK_HASHES).sort();
  const offered = Object.keys(s.vkHashes).sort();
  if (pinned.join() !== offered.join() || pinned.some((t) => s.vkHashes[t] !== PINNED_VK_HASHES[t])) problems.push('verification keys');
  const text = encodeStatement(s);
  if (text !== ch.statementText) problems.push('statement text');
  if ((await statementChallenge(s)) !== ch.challenge) problems.push('challenge');
  if (problems.length > 0) throw new Error(`the verifier asked to sign a different statement (${problems.join(', ')} differ). Nothing was signed.`);
  return ch;
}

/** Signs a checked statement with the passkey and submits it. */
export async function signAndSubmit(api: Api, ch: ChallengeResponse) {
  const response = await startAuthentication({
    optionsJSON: {
      challenge: ch.challenge,
      rpId: ch.rpId,
      allowCredentials: ch.allowCredentials.map((c) => ({ id: c.id, type: 'public-key' as const, ...(c.transports ? { transports: [...c.transports] as AuthenticatorTransport[] as never } : {}) })),
      userVerification: 'required',
      timeout: ch.timeoutMs,
    },
  });
  const path = ch.statement.action === 'register' ? '/api/policies/register' : '/api/policies/revoke';
  return api.post<{ ok: boolean; status?: string; reason?: string }>(path, { policyCommitment: ch.statement.policyCommitment, nonce: ch.statement.nonce, response });
}
