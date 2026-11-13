/**
 * The dashboard's own check before it asks the passkey to sign: whatever the server relays, the
 * statement must be this action, on this commitment, under this protocol label and the pinned
 * verification keys, and its text and challenge must be the canonical ones. A server that lies
 * consistently (text and challenge recomputed over its altered statement) is still caught.
 */
import { describe, expect, it } from 'vitest';
import type { ChallengeResponse } from '../src/shared/api.ts';
import { APPROVAL_LABEL, type ApprovalStatement, encodeStatement, PINNED_VK_HASHES, statementChallenge } from '../src/shared/approval.ts';
import { requestStatement } from '../src/web/passkey.ts';
import type { Api } from '../src/web/api.ts';

const COMMITMENT = '0x' + '2a'.repeat(32);
const statement: ApprovalStatement = { label: APPROVAL_LABEL, action: 'register', policyCommitment: COMMITMENT, vkHashes: { ...PINNED_VK_HASHES }, nonce: 'n'.repeat(43) };

async function relayed(s: ApprovalStatement, patch: Partial<ChallengeResponse> = {}): Promise<ChallengeResponse> {
  return { statement: s, statementText: encodeStatement(s), challenge: await statementChallenge(s), rpId: 'localhost', allowCredentials: [], timeoutMs: 1000, ...patch };
}
const api = (r: ChallengeResponse) => ({ post: async () => r }) as unknown as Api;

describe('the dashboard refuses to sign anything but the requested approval', () => {
  it('accepts the honest statement (control)', async () => {
    await expect(requestStatement(api(await relayed(statement)), 'register', COMMITMENT)).resolves.toMatchObject({ statement });
  });

  const lies: [string, Partial<ApprovalStatement>, RegExp][] = [
    ['another label', { label: 'zkif.policy-approval.v0' }, /protocol label/],
    ['another action', { action: 'revoke' }, /action/],
    ['another commitment', { policyCommitment: '0x' + '2b'.repeat(32) }, /policy commitment/],
    ['another key hash', { vkHashes: { ...PINNED_VK_HASHES, evm: '0x' + '00'.repeat(32) } }, /verification keys/],
    ['a key missing', { vkHashes: { 'noir-recursive': PINNED_VK_HASHES['noir-recursive']! } }, /verification keys/],
    ['an extra key', { vkHashes: { ...PINNED_VK_HASHES, ultra: '0x' + '11'.repeat(32) } }, /verification keys/],
  ];
  for (const [name, patch, why] of lies) {
    it(`refuses ${name}, even with matching text and challenge`, async () => {
      await expect(requestStatement(api(await relayed({ ...statement, ...patch })), 'register', COMMITMENT)).rejects.toThrow(why);
    });
  }

  it('refuses display text that differs from the statement', async () => {
    const r = await relayed(statement, { statementText: encodeStatement({ ...statement, policyCommitment: '0x' + '2b'.repeat(32) }) });
    await expect(requestStatement(api(r), 'register', COMMITMENT)).rejects.toThrow(/statement text/);
  });

  it('refuses a challenge that is not the statement’s', async () => {
    const r = await relayed(statement, { challenge: await statementChallenge({ ...statement, action: 'revoke' }) });
    await expect(requestStatement(api(r), 'register', COMMITMENT)).rejects.toThrow(/challenge/);
  });
});
