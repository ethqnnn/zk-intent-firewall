/**
 * Who is asking, for rate limiting and the public log. The client's address is turned into a keyed
 * hash with a secret drawn at boot, and the address itself is never stored or shown.
 */
import { createHmac, randomBytes } from 'node:crypto';
import type { IncomingMessage } from 'node:http';

/**
 * Where the client address comes from:
 *   - `socket`: the TCP peer. Right when nothing sits in front of the server.
 *   - `x-forwarded-for`: the entry `hops` from the right of X-Forwarded-For. Entries a client
 *     sends itself are to the left of the ones the proxies add, so this cannot be spoofed as long
 *     as `hops` matches the number of proxies in front (1 on Railway).
 *   - `x-real-ip`: the X-Real-IP header, for proxies that set it and drop any client copy.
 */
export type ClientIpSource = 'socket' | 'x-forwarded-for' | 'x-real-ip';

export function clientAddress(req: IncomingMessage, source: ClientIpSource, hops = 1): string {
  const socket = req.socket.remoteAddress ?? 'unknown';
  if (source === 'x-real-ip') {
    const v = req.headers['x-real-ip'];
    return typeof v === 'string' && v.trim().length > 0 ? v.trim().slice(0, 64) : socket;
  }
  if (source === 'x-forwarded-for') {
    const v = req.headers['x-forwarded-for'];
    const entries = (Array.isArray(v) ? v.join(',') : (v ?? '')).split(',').map((s) => s.trim()).filter((s) => s.length > 0);
    const pick = entries[entries.length - Math.max(1, hops)];
    return pick !== undefined ? pick.slice(0, 64) : socket;
  }
  return socket;
}

export class ClientKeys {
  readonly #secret: Buffer;

  constructor(secret: Buffer = randomBytes(32)) {
    this.#secret = secret;
  }

  /** A stable, unlinkable key for an address, for this process's lifetime. */
  key(address: string): string {
    return createHmac('sha256', this.#secret).update(address).digest('hex').slice(0, 24);
  }
}

/** `anon-` and six hex digits of the key: how an anonymous visitor appears in the public log. */
export function pseudonym(key: string): string {
  return `anon-${key.slice(0, 6)}`;
}

const HANDLE = /^[A-Za-z0-9_.-]{2,24}$/;

/** A visitor's chosen handle, or undefined if it is not acceptable. `anon-` is reserved. */
export function handleOf(x: unknown): string | undefined {
  if (typeof x !== 'string' || !HANDLE.test(x) || /^anon-/i.test(x)) return undefined;
  return x;
}
