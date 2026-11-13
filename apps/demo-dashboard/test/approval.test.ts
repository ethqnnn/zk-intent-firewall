/**
 * The approval statement: its canonical text, its challenge, and agreement between the copies of
 * the pinned key hashes in the browser bundle, in mcp-firewall and in the circuit's fixtures.
 */
import { PINNED_VERIFICATION_KEYS, VERIFIER_TARGETS } from '@zk-intent-firewall/mcp-firewall';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { APPROVAL_LABEL, type ApprovalStatement, encodeStatement, newApprovalNonce, PINNED_VK_HASHES, StatementError, statementChallenge } from '../src/shared/approval.ts';

const base: ApprovalStatement = {
  label: APPROVAL_LABEL,
  action: 'register',
  policyCommitment: '0x' + '1f'.repeat(32),
  vkHashes: PINNED_VK_HASHES,
  nonce: 'A'.repeat(43),
};

describe('approval statement', () => {
  it('has a fixed, line-based canonical form with the key hashes sorted by target', () => {
    expect(encodeStatement(base)).toBe(
      [
        'zkif.policy-approval.v1',
        'action: register',
        `policy_commitment: 0x${'1f'.repeat(32)}`,
        'vk_hash.evm: 0x0ada696cfd9ba778ed3c2b4d1cb79a4efc0e9a389f2561cd86d6f5b1eba9557b',
        'vk_hash.noir-recursive: 0x15bd93c9bb5f2c9bfe73268360c1a69892eb13777e084bdc282d2125fb6cb3de',
        `nonce: ${'A'.repeat(43)}`,
        '',
      ].join('\n'),
    );
    // Key order in the object does not matter.
    const reversed = { ...base, vkHashes: { 'noir-recursive': PINNED_VK_HASHES['noir-recursive']!, evm: PINNED_VK_HASHES['evm']! } };
    expect(encodeStatement(reversed)).toBe(encodeStatement(base));
  });

  it('challenge is base64url(SHA-256(statement text))', async () => {
    const expected = createHash('sha256').update(encodeStatement(base), 'utf8').digest('base64url');
    expect(await statementChallenge(base)).toBe(expected);
  });

  it('every field changes the challenge', async () => {
    const c0 = await statementChallenge(base);
    const variants: ApprovalStatement[] = [
      { ...base, label: 'zkif.policy-approval.v2' },
      { ...base, action: 'revoke' },
      { ...base, policyCommitment: '0x' + '1f'.repeat(31) + '20' },
      { ...base, vkHashes: { ...PINNED_VK_HASHES, evm: '0x' + '00'.repeat(32) } },
      { ...base, vkHashes: { 'noir-recursive': PINNED_VK_HASHES['noir-recursive']! } },
      { ...base, nonce: 'B' + 'A'.repeat(42) },
    ];
    for (const v of variants) expect(await statementChallenge(v)).not.toBe(c0);
  });

  it('refuses anything off-format instead of encoding it', () => {
    const bad: Partial<ApprovalStatement>[] = [
      { label: 'zkif policy\napproval' },
      { action: 'approve' as never },
      { policyCommitment: '0x' + '1F'.repeat(32) }, // uppercase is not canonical
      { policyCommitment: '0x1234' },
      { policyCommitment: '1f'.repeat(32) },
      { vkHashes: {} },
      { vkHashes: { 'evm\nnonce': PINNED_VK_HASHES['evm']! } },
      { vkHashes: { evm: '0x0ada' } },
      { nonce: 'short' },
      { nonce: 'A'.repeat(42) + '=' },
    ];
    for (const b of bad) expect(() => encodeStatement({ ...base, ...b })).toThrow(StatementError);
  });

  it('nonces are 32 fresh random bytes', () => {
    const a = newApprovalNonce();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(a, 'base64url')).toHaveLength(32);
    expect(newApprovalNonce()).not.toBe(a);
  });
});

describe('pinned verification key hashes', () => {
  it('the browser copy equals mcp-firewall PINNED_VERIFICATION_KEYS', () => {
    expect(Object.keys(PINNED_VK_HASHES).sort()).toEqual([...VERIFIER_TARGETS].sort());
    for (const t of VERIFIER_TARGETS) expect(PINNED_VK_HASHES[t]).toBe(PINNED_VERIFICATION_KEYS[t].bbHash);
  });

  it('and the circuit fixture vk_hashes.txt', () => {
    const file = readFileSync(new URL('../../../packages/zk-circuit/fixtures/vk_hashes.txt', import.meta.url), 'utf8');
    const recorded = Object.fromEntries(
      file
        .split('\n')
        .filter((l) => l && !l.startsWith('#'))
        .map((l) => l.split(' ') as [string, string]),
    );
    expect(recorded).toEqual({ ...PINNED_VK_HASHES });
  });
});
