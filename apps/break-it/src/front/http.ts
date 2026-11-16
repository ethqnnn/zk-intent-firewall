/**
 * The public HTTP interface. No authentication: anyone may attack. In front of the engine it adds
 * only what a public service needs:
 *
 *   - per-client rate limits by route class, and a global budget for requests that may prove;
 *   - concurrency gates that refuse rather than queue without bound;
 *   - body size limits, JSON-only POSTs, and a same-origin check when a browser sends an Origin,
 *     so another site cannot drive visitors' browsers into attacking;
 *   - the fake-money notice on every response;
 *   - the public log of every attempt.
 */
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { extname, join, resolve } from 'node:path';
import { cleanText } from '../engine/summary.ts';
import { FAKE_MONEY_HEADER, FAKE_MONEY_HEADER_VALUE, FAKE_MONEY_NOTICE, FAKE_UNIT, LINKS } from '../shared/notice.ts';
import type { AttemptRecord, AttemptRoute, EngineAnswer, StatusView } from '../shared/types.ts';
import type { AttemptLog } from './attempt-log.ts';
import { ClientKeys, clientAddress, handleOf, pseudonym } from './client.ts';
import type { FrontConfig } from './config.ts';
import { Gate, RateLimiter } from './limits.ts';

export const MAX_BODY_BYTES = 128 * 1024;

export interface EngineClient {
  readonly policyCommitment: string;
  call<T>(method: string, params: unknown, timeoutMs?: number): Promise<T>;
}

export interface FrontDeps {
  readonly config: FrontConfig;
  readonly engine: EngineClient;
  readonly log: AttemptLog;
  readonly staticDir: string;
  /** The engine's sandbox self-check at boot. */
  readonly sandbox: Readonly<Record<string, string>>;
  readonly keys?: ClientKeys;
}

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
};

/** Clean URL paths to files in the static directory. Nothing else is served. */
const PAGES: Record<string, string> = {
  '/': 'index.html',
  '/log': 'log.html',
  '/style.css': 'style.css',
  '/app.js': 'app.js',
  '/log.js': 'log.js',
  '/common.js': 'common.js',
  '/favicon.svg': 'favicon.svg',
  '/robots.txt': 'robots.txt',
};

const ATTEMPT_ROUTES: Record<string, { route: AttemptRoute; method: string; limit: 'agent' | 'direct' | 'passkey' }> = {
  '/api/attempt/agent': { route: 'agent', method: 'attempt.agent', limit: 'agent' },
  '/api/attempt/direct': { route: 'direct', method: 'attempt.direct', limit: 'direct' },
  '/api/attempt/passkey': { route: 'passkey', method: 'attempt.passkey', limit: 'passkey' },
  '/api/attempt/enroll': { route: 'enroll', method: 'attempt.enroll', limit: 'passkey' },
};

export function createFront(d: FrontDeps) {
  const { config } = d;
  const keys = d.keys ?? new ClientKeys();
  const perMinute = (l: { burst: number; perMinute: number }) => new RateLimiter({ capacity: l.burst, refillPerSecond: l.perMinute / 60 });
  const limiters = {
    agent: perMinute(config.limits.agent),
    direct: perMinute(config.limits.direct),
    passkey: perMinute(config.limits.passkey),
    read: perMinute(config.limits.read),
  };
  const globalProving = perMinute(config.limits.globalProving);
  const gates = { agent: new Gate(config.gates.agent), direct: new Gate(config.gates.direct), passkey: new Gate(config.gates.passkey) };
  const pages = new Map<string, Buffer>();

  let statusCache: { at: number; value: StatusView } | undefined;
  const engineStatus = async (): Promise<StatusView> => {
    if (statusCache && Date.now() - statusCache.at < 2000) return statusCache.value;
    const value = await d.engine.call<StatusView>('status', {}, 10_000);
    statusCache = { at: Date.now(), value };
    return value;
  };

  const publicLimits = () => ({
    perClient: Object.fromEntries(Object.entries(config.limits).filter(([k]) => k !== 'globalProving')),
    globalProving: config.limits.globalProving,
    concurrency: config.gates,
  });

  return async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader(FAKE_MONEY_HEADER, FAKE_MONEY_HEADER_VALUE);
    if (config.origin.startsWith('https://')) res.setHeader('Strict-Transport-Security', 'max-age=31536000');

    let url: URL;
    try {
      url = new URL(req.url ?? '/', config.origin);
    } catch {
      return json(res, 400, { error: 'bad request' });
    }
    const path = url.pathname;
    const client = keys.key(clientAddress(req, config.clientIpSource, config.proxyHops));

    if (path === '/healthz') return json(res, 200, { ok: true });

    if (!path.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'method not allowed' });
      const file = PAGES[path];
      if (file === undefined) return json(res, 404, { error: 'not found' });
      let body = pages.get(file);
      if (body === undefined) {
        try {
          body = await readFile(join(resolve(d.staticDir), file));
          pages.set(file, body);
        } catch {
          return json(res, 404, { error: 'not found' });
        }
      }
      res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Content-Security-Policy': CSP, 'Cache-Control': 'public, max-age=300' });
      return void res.end(req.method === 'HEAD' ? undefined : body);
    }

    res.setHeader('Cache-Control', 'no-store');

    try {
      if (req.method === 'GET') {
        const r = limiters.read.take(client);
        if (!r.ok) return tooMany(res, r.retryAfterSeconds);
        switch (path) {
          case '/api/status':
            return json(res, 200, {
              engine: await engineStatus(),
              sandbox: d.sandbox,
              log: summary(d.log.stats()),
              limits: publicLimits(),
              links: LINKS,
              unit: FAKE_UNIT,
              you: { who: pseudonym(client) },
            });
          case '/api/log': {
            const q = url.searchParams;
            const id = q.get('id');
            if (id) {
              const r1 = d.log.get(id);
              return r1 ? json(res, 200, { attempt: r1 }) : json(res, 404, { error: 'no such attempt in the recent log' });
            }
            const s = (k: string) => q.get(k)?.slice(0, 64) || undefined;
            const limit = Number(q.get('limit') ?? '50');
            const filter = { limit: Number.isFinite(limit) ? limit : 50, before: s('before'), verdict: s('verdict'), layer: s('layer'), check: s('check'), who: s('who'), route: s('route') };
            return json(res, 200, { attempts: d.log.list(Object.fromEntries(Object.entries(filter).filter(([, v]) => v !== undefined))) });
          }
          case '/api/leaderboard':
            return json(res, 200, { leaderboard: d.log.leaderboard(), stats: summary(d.log.stats()) });
          case '/api/whoami':
            return json(res, 200, {
              who: pseudonym(client),
              remaining: Object.fromEntries(Object.entries(limiters).map(([k, l]) => [k, l.remaining(client)])),
              limits: publicLimits(),
            });
          case '/api/passkey/challenge': {
            const p = limiters.passkey.take(client);
            if (!p.ok) return tooMany(res, p.retryAfterSeconds);
            const query = { action: url.searchParams.get('action'), policyCommitment: url.searchParams.get('policyCommitment') };
            const ran = await gates.passkey.run(() => d.engine.call<EngineAnswer>('passkey.challenge', { client, body: query }));
            if (!ran) return busy(res);
            return json(res, ran.value.http, ran.value.response);
          }
          default:
            return json(res, 404, { error: 'not found' });
        }
      }

      if (req.method === 'POST') {
        const spec = ATTEMPT_ROUTES[path];
        if (!spec) return json(res, 404, { error: 'not found' });
        // Browsers send Origin on every POST; scripts and curl usually send none, which is fine.
        const origin = req.headers.origin;
        if (origin !== undefined && origin !== config.origin) return json(res, 403, { error: 'cross-origin requests are refused; call the API directly or use this page' });
        if (!/^application\/json\b/i.test(req.headers['content-type'] ?? '')) return json(res, 415, { error: 'send a JSON body with Content-Type: application/json' });
        const r = limiters[spec.limit].take(client);
        if (!r.ok) return tooMany(res, r.retryAfterSeconds);
        if (spec.route === 'agent') {
          const g = globalProving.take('global');
          if (!g.ok) return busy(res, g.retryAfterSeconds, 'the global proving budget is used up for the moment');
        }
        let body: unknown;
        try {
          body = await readJson(req);
        } catch (e) {
          return json(res, e instanceof BodyTooLarge ? 413 : 400, { error: e instanceof Error ? e.message : 'invalid body' });
        }
        const b = (typeof body === 'object' && body !== null && !Array.isArray(body) ? body : {}) as Record<string, unknown>;
        const who = handleOf(b['handle']) ?? pseudonym(client);
        const note = cleanText(b['note'], 280);
        const engineBody = typeof body === 'object' && body !== null && !Array.isArray(body) ? Object.fromEntries(Object.entries(b).filter(([k]) => k !== 'handle' && k !== 'note')) : body;

        const ran = await gates[spec.limit].run(() => d.engine.call<EngineAnswer>(spec.method, { client, body: engineBody }));
        if (!ran) return busy(res);
        // The ledger or registry may have changed: the next status read goes to the engine.
        statusCache = undefined;
        const a = ran.value;
        let record: AttemptRecord | undefined;
        if (a.draft) {
          record = { id: randomUUID(), at: new Date().toISOString(), policyCommitment: d.engine.policyCommitment, who, ...(note ? { note } : {}), ...a.draft };
          d.log.add(record);
        }
        return json(res, a.http, { ...(record ? { attempt: record, logUrl: `${config.origin}/log#${record.id}` } : {}), ...a.response });
      }

      return json(res, 405, { error: 'method not allowed' });
    } catch (e) {
      const message = e instanceof Error && /timed out/.test(e.message) ? 'the engine took too long; try again' : 'internal error';
      return json(res, 503, { error: message });
    }
  };
}

function summary(s: ReturnType<AttemptLog['stats']>) {
  return { ...s, breaks: s.breaks.slice(0, 20) };
}

class BodyTooLarge extends Error {}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolveBody, reject) => {
    const declared = Number(req.headers['content-length'] ?? '0');
    if (declared > MAX_BODY_BYTES) {
      reject(new BodyTooLarge(`the body must be at most ${MAX_BODY_BYTES} bytes`));
      req.resume();
      return;
    }
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new BodyTooLarge(`the body must be at most ${MAX_BODY_BYTES} bytes`));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolveBody(chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('the body is not valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  if (res.headersSent) return void res.end();
  const s = JSON.stringify({ environment: FAKE_MONEY_NOTICE, ...body });
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" });
  res.end(s);
}

function tooMany(res: ServerResponse, retryAfterSeconds: number): void {
  res.setHeader('Retry-After', String(retryAfterSeconds));
  json(res, 429, { error: 'rate limit: slow down', retryAfterSeconds });
}

function busy(res: ServerResponse, retryAfterSeconds = 5, why = 'the server is at capacity'): void {
  res.setHeader('Retry-After', String(retryAfterSeconds));
  json(res, 503, { error: `${why}; try again shortly`, retryAfterSeconds });
}
