/**
 * The host's HTTP interface, for the dashboard only.
 *
 * - Every /api route requires the session token in the x-zkif-session header. The token is printed
 *   in the terminal as a URL fragment, which browsers never send to a server.
 * - Every POST also requires an Origin header equal to the dashboard's origin and a JSON body, so a
 *   page on another site cannot drive the API from a visitor's browser.
 * - No route returns a policy opening. The opening arrives with POST /api/firewall/arm and stays in
 *   the firewall's memory.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import type { HostEvent } from '../../shared/api.ts';
import { SESSION_HEADER } from '../../shared/api.ts';
import { INBOX } from '../../demo/inbox.ts';
import { type Host, HostError } from './host.ts';

const MAX_BODY = 64 * 1024;

export interface HttpOptions {
  /** Serve the built dashboard from this directory. */
  readonly staticDir?: string;
  /** Or hand non-API requests to Vite's dev middleware. */
  readonly devMiddleware?: (req: IncomingMessage, res: ServerResponse, next: () => void) => void;
}

type Handler = (body: unknown, req: IncomingMessage) => Promise<unknown>;

export function createRequestHandler(host: Host, o: HttpOptions = {}) {
  const post: Record<string, Handler> = {
    '/api/passkey/options': async () => host.passkeyOptions(),
    '/api/passkey/verify': async (b) => host.passkeyComplete((b as { response?: unknown })?.response),
    '/api/policies/prepare': async (b) => host.preparePolicy(b as never),
    '/api/approvals/challenge': async (b) => host.approvalChallenge(b as never),
    '/api/policies/register': async (b) => host.registerPolicy(b as never),
    '/api/policies/revoke': async (b) => host.revokePolicy(b as never),
    '/api/policies/records': async (b) => host.policyRecords((b as { commitments?: unknown })?.commitments),
    '/api/firewall/arm': async (b) => ({ policyCommitment: await host.arm((b as { opening?: unknown })?.opening) }),
    '/api/firewall/disarm': async () => (host.disarm(), { ok: true }),
    '/api/demo/run': async (b) => {
      // Respond at once; progress is streamed on /api/events.
      const p = host.runDemo((b ?? {}) as never);
      p.catch(() => undefined);
      return { started: true };
    },
  };
  const get: Record<string, () => Promise<unknown>> = {
    '/api/state': () => host.state(),
    '/api/log': () => host.log(),
    // The demo inbox, with the hostile messages marked, for the dashboard's narration. Public demo data.
    '/api/inbox': async () => INBOX,
  };

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', host.origin);
    const path = url.pathname;
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');

    if (path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
      if (!host.checkToken(req.headers[SESSION_HEADER])) return json(res, 401, { error: 'missing or wrong session token' });

      if (req.method === 'GET' && path === '/api/events') return events(host, req, res);
      if (req.method === 'GET' && Object.hasOwn(get, path)) return respond(res, () => get[path]!());
      if (req.method === 'POST' && Object.hasOwn(post, path)) {
        if (req.headers.origin !== host.origin) return json(res, 403, { error: 'cross-origin request refused' });
        if (!/^application\/json\b/.test(req.headers['content-type'] ?? '')) return json(res, 415, { error: 'JSON body required' });
        let body: unknown;
        try {
          body = await readJson(req);
        } catch (e) {
          return json(res, 400, { error: e instanceof Error ? e.message : 'invalid body' });
        }
        return respond(res, () => post[path]!(body, req));
      }
      return json(res, 404, { error: 'not found' });
    }

    if (o.devMiddleware) return o.devMiddleware(req, res, () => json(res, 404, { error: 'not found' }));
    if (o.staticDir) return serveStatic(o.staticDir, path, res);
    json(res, 404, { error: 'not found' });
  };
}

async function respond(res: ServerResponse, f: () => Promise<unknown>): Promise<void> {
  try {
    json(res, 200, await f());
  } catch (e) {
    if (e instanceof HostError) json(res, e.status, { error: e.message });
    else json(res, 500, { error: 'internal error' });
  }
}

function json(res: ServerResponse, status: number, body: unknown): void {
  if (res.headersSent) return void res.end();
  const s = JSON.stringify(body, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(s);
}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolveBody, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolveBody(chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('body is not JSON'));
      }
    });
    req.on('error', reject);
  });
}

function events(host: Host, req: IncomingMessage, res: ServerResponse): void {
  res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
  res.write(': connected\n\n');
  const send = (e: HostEvent) => res.write(`data: ${JSON.stringify(e)}\n\n`);
  const unsubscribe = host.subscribe(send);
  const ping = setInterval(() => res.write(': ping\n\n'), 15_000);
  req.on('close', () => {
    clearInterval(ping);
    unsubscribe();
  });
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.woff2': 'font/woff2',
};

const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

async function serveStatic(dir: string, path: string, res: ServerResponse): Promise<void> {
  const root = resolve(dir);
  let file = resolve(join(root, normalize(decodeURIComponent(path))));
  if (!file.startsWith(root)) return json(res, 404, { error: 'not found' });
  if (path === '/' || !extname(file)) file = join(root, 'index.html');
  try {
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream', 'Content-Security-Policy': CSP, 'X-Frame-Options': 'DENY' });
    res.end(body);
  } catch {
    json(res, 404, { error: 'not found' });
  }
}
