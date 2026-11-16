/**
 * Short, safe descriptions of what someone sent, for the public log. Proofs and WebAuthn blobs are
 * reduced to sizes and hash prefixes; every string is cut to a bounded length.
 */
import { createHash } from 'node:crypto';
import { INTENT_META_KEY } from '@zk-intent-firewall/mcp-firewall';
import type { EnvelopeSummary } from '../shared/types.ts';

export const MAX_ARGS_CHARS = 600;

export function clip(s: string, n: number): string {
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

// Control characters, line and paragraph separators, and bidirectional overrides.
const UNSAFE_CHARS = new RegExp('[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]', 'g');

/** Strips control characters and cuts to `n` characters. Undefined for anything but a string. */
export function cleanText(x: unknown, n: number): string | undefined {
  if (typeof x !== 'string') return undefined;
  const s = x.replace(UNSAFE_CHARS, ' ').trim();
  return s.length === 0 ? undefined : clip(s, n);
}

export function argumentsSummary(args: unknown): string {
  let s: string;
  try {
    s = JSON.stringify(args) ?? 'undefined';
  } catch {
    s = '[unserialisable]';
  }
  return clip(s, MAX_ARGS_CHARS);
}

const str = (x: unknown, n: number): string | undefined => (typeof x === 'string' ? clip(x, n) : undefined);

export function envelopeSummary(meta: unknown): EnvelopeSummary | null {
  const raw = typeof meta === 'object' && meta !== null ? (meta as Record<string, unknown>)[INTENT_META_KEY] : undefined;
  if (raw === undefined) return null;
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { malformed: true };
  const w = raw as Record<string, unknown>;
  const out: { -readonly [K in keyof EnvelopeSummary]: EnvelopeSummary[K] } = {};
  const target = str(w['target'], 32);
  const pc = str(w['policy_commitment'], 80);
  const ts = str(w['current_timestamp'], 32);
  const nonce = str(w['nonce'], 80);
  if (target !== undefined) out.target = target;
  if (pc !== undefined) out.policy_commitment = pc;
  if (ts !== undefined) out.current_timestamp = ts;
  if (nonce !== undefined) out.nonce = nonce;
  if (typeof w['proof'] === 'string') {
    const bytes = Buffer.from(w['proof'], 'base64');
    out.proofBytes = bytes.length;
    out.proofSha256 = createHash('sha256').update(bytes).digest('hex').slice(0, 16);
  }
  return out;
}

export function metaKeys(meta: unknown): string[] {
  if (typeof meta !== 'object' || meta === null) return [];
  return Object.keys(meta)
    .filter((k) => k !== INTENT_META_KEY)
    .slice(0, 8)
    .map((k) => clip(k, 48));
}

/** The JSON size of `x`, or Infinity when it cannot be serialised. */
export function jsonSize(x: unknown): number {
  try {
    return JSON.stringify(x)?.length ?? 0;
  } catch {
    return Infinity;
  }
}
