/**
 * Identifier encoding (docs/circuit-spec.md, section 10.4). The circuit treats `tool_id`,
 * `recipient` and `nonce` as opaque field elements; this module owns how they are derived.
 *
 *   to_field(domain, part_1, ..., part_k) =
 *       the first 31 bytes of SHA-256(domain || 0x0A || part_1 || 0x0A || ... || part_k),
 *       read as a big-endian integer
 */
import { createHash, getRandomValues } from 'node:crypto';

export const DOMAIN_TOOL = 'zkif.tool.v1';
export const DOMAIN_RECIPIENT = 'zkif.recipient.v1';

/** Always a canonical field element: 31 bytes are below 2^248 < p. */
export function toField(domain: string, ...parts: string[]): bigint {
  for (const s of [domain, ...parts]) {
    if (typeof s !== 'string' || s.includes('\n')) throw new Error('identifier parts are strings without a line feed');
  }
  const digest = createHash('sha256').update([domain, ...parts].join('\n'), 'utf8').digest();
  return BigInt('0x' + digest.subarray(0, 31).toString('hex'));
}

/**
 * `tool_id = to_field("zkif.tool.v1", server_id, tool_name)`. `serverId` must identify the tool
 * server, not only the tool, so that a proof made for one server cannot be replayed at another.
 */
export function toolId(serverId: string, toolName: string): bigint {
  return toField(DOMAIN_TOOL, serverId, toolName);
}

/**
 * `recipient = to_field("zkif.recipient.v1", asset_id, account_id)`, with a CAIP-19 asset and a
 * CAIP-10 account. The recipient commits to network, asset and account, so a limit meant for one
 * asset never authorises another (spec, L5).
 */
export function recipientId(assetId: string, accountId: string): bigint {
  return toField(DOMAIN_RECIPIENT, assetId, accountId);
}

/** 31 bytes from the platform CSPRNG, read as a big-endian integer. Never zero. */
export function randomField31(): bigint {
  for (;;) {
    const x = BigInt('0x' + Buffer.from(getRandomValues(new Uint8Array(31))).toString('hex'));
    if (x !== 0n) return x;
  }
}

/** A fresh policy salt (spec 5.5). */
export const randomSalt = randomField31;
/** A fresh per-call nonce with 248 bits of entropy (spec 10.4). */
export const randomNonce = randomField31;
