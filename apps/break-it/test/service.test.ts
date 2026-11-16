/**
 * The whole service as deployed: the front process, the sandboxed engine, real HTTP. Checks the
 * fake-money labelling, the sandbox, the API guards, rate limiting, and that the public log
 * records each attempt accurately, persists it, and reloads it after a restart.
 */
import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BREAK_IT_POLICY, NOT_ALLOWLISTED } from '../src/engine/deployment.ts';
import { FAKE_MONEY_NOTICE } from '../src/shared/notice.ts';

const APP = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const NORTHWIND = BREAK_IT_POLICY.payees[0]!.account;

function freePort(): Promise<number> {
  return new Promise((r) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => r(p));
    });
  });
}

interface Service {
  readonly base: string;
  readonly child: ChildProcess;
  output(): string;
  stop(): Promise<void>;
}

async function start(dataDir: string, extraEnv: Record<string, string> = {}): Promise<Service> {
  const port = await freePort();
  const child = spawn(process.execPath, ['src/front/main.ts'], {
    cwd: APP,
    env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '', PORT: String(port), HOST: '127.0.0.1', BREAKIT_DATA_DIR: dataDir, BREAKIT_PROVER_THREADS: '4', ...extraEnv },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout!.on('data', (b: Buffer) => (out += b.toString()));
  child.stderr!.on('data', (b: Buffer) => (out += b.toString()));
  await new Promise<void>((ok, fail) => {
    const t = setInterval(() => {
      if (out.includes('listening on')) {
        clearInterval(t);
        ok();
      }
    }, 100);
    child.once('exit', (code) => {
      clearInterval(t);
      fail(new Error(`service exited with ${code}:\n${out}`));
    });
  });
  return {
    base: `http://127.0.0.1:${port}`,
    child,
    output: () => out,
    stop: async () => {
      if (child.exitCode !== null) return;
      const exited = new Promise((r) => child.once('exit', r));
      child.kill('SIGTERM');
      await exited;
    },
  };
}

let svc: Service;
let dataDir: string;

beforeAll(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'break-it-svc-'));
  svc = await start(dataDir, { BREAKIT_LIMIT_DIRECT_BURST: '4', BREAKIT_LIMIT_DIRECT_PER_MINUTE: '1' });
});
afterAll(async () => {
  await svc?.stop();
  rmSync(dataDir, { recursive: true, force: true });
});

const get = async (path: string, headers: Record<string, string> = {}) => {
  const r = await fetch(svc.base + path, { headers });
  return { status: r.status, headers: r.headers, body: (await r.json()) as Record<string, any> };
};
const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
  const r = await fetch(svc.base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  return { status: r.status, headers: r.headers, body: (await r.json()) as Record<string, any> };
};
const balance = async () => BigInt((await get('/api/status')).body.engine.ledger.treasury.balance);

describe('the service', () => {
  it('refuses to be mistaken for real money: notice in every JSON body and a header on every response', async () => {
    for (const r of [await get('/api/status'), await get('/api/log'), await get('/api/nope'), await post('/api/attempt/agent', '{bad')]) {
      expect(r.body.environment).toBe(FAKE_MONEY_NOTICE);
      expect(r.headers.get('x-fake-money')).toMatch(/^true; this is a test environment/);
    }
    const page = await fetch(`${svc.base}/`);
    expect(page.headers.get('x-fake-money')).toMatch(/^true/);
    expect(await page.text()).toContain('FAKE MONEY');
  });

  it('started its engine in a sandbox with no network, no processes and no writes, and says so', async () => {
    const { body } = await get('/api/status');
    expect(body.sandbox).toMatchObject({ network: 'ERR_ACCESS_DENIED', fetch: 'ERR_ACCESS_DENIED', childProcess: 'ERR_ACCESS_DENIED', fileWrite: 'ERR_ACCESS_DENIED', fileReadOutside: 'ERR_ACCESS_DENIED' });
    expect(body.sandbox.env.split(',')).toEqual(['BREAKIT_AUTO_TOP_UP', 'BREAKIT_CRS_PATH', 'BREAKIT_ORIGIN', 'BREAKIT_PROVER_THREADS', 'NODE_NO_WARNINGS']);
    expect(body.engine.verifier.registry.status).toBe('active');
    expect(body.engine.ledger.treasury).toEqual({ openingBalance: '10000000000', balance: '10000000000' });
    expect(body.links.reportVulnerability).toBe('https://github.com/ethqnnn/zk-intent-firewall/security/advisories/new');
  });

  it('serves the pages with a strict CSP, and nothing outside its page list', async () => {
    for (const p of ['/', '/log', '/style.css', '/app.js', '/log.js', '/common.js']) {
      const r = await fetch(svc.base + p);
      expect(r.status, p).toBe(200);
      expect(r.headers.get('content-security-policy')).toContain("script-src 'self'");
    }
    for (const p of ['/package.json', '/../package.json', '/src/front/main.ts', '/%2e%2e/package.json']) expect((await fetch(svc.base + p)).status, p).toBe(404);
  });

  it('guards the API: same origin for browsers, JSON only, bounded bodies', async () => {
    expect((await post('/api/attempt/agent', { tool: 'get_balance' }, { origin: 'https://evil.example' })).status).toBe(403);
    expect((await fetch(`${svc.base}/api/attempt/agent`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'tool=get_balance' })).status).toBe(415);
    expect((await post('/api/attempt/agent', { tool: 'get_balance', pad: 'x'.repeat(200_000) })).status).toBe(413);
    expect((await post('/api/attempt/agent', { tool: 'get_balance' }, { origin: (await get('/api/status')).body.engine.verifier.origin })).status).toBe(200);
  });
});

describe('the public log records each attempt accurately', () => {
  it('a legitimate payment: logged as executed and legitimate, with the handle, the note and the exact debit', async () => {
    const before = await balance();
    const r = await post('/api/attempt/agent', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: '7000000' }, handle: 'alice', note: 'control: an in-policy payment' });
    expect(r.status).toBe(200);
    expect(await balance()).toBe(before - 7_000_000n);
    const a = r.body.attempt;
    expect(a).toMatchObject({
      who: 'alice',
      note: 'control: an in-policy payment',
      route: 'agent',
      attempted: { tool: 'send_payment', arguments: JSON.stringify({ recipient: NORTHWIND, amount: '7000000' }), mode: 'forward', precheck: true },
      result: 'executed',
      verdict: 'legitimate',
      caughtBy: null,
      payment: { tool: 'send_payment', recipient: NORTHWIND, amount: '7000000' },
      policyCommitment: (await get('/api/status')).body.engine.policy.policyCommitment,
    });
    expect(Date.now() - Date.parse(a.at)).toBeLessThan(60_000);
    expect((await get(`/api/log?id=${a.id}`)).body.attempt).toEqual(a);
  });

  it('a blocked payment: logged with the named check, and the ledger untouched', async () => {
    const before = await balance();
    const r = await post('/api/attempt/agent', { tool: 'send_payment', arguments: { recipient: NOT_ALLOWLISTED.lookalike.account, amount: '1000000' }, handle: 'mallory' });
    expect(await balance()).toBe(before);
    expect(r.body.attempt).toMatchObject({ who: 'mallory', result: 'blocked', verdict: 'caught', caughtBy: { layer: 'firewall', check: 'recipient_not_allowlisted' } });
    expect(r.body.agentSees).toMatch(/^Blocked by the intent firewall/);
  });

  it('a direct attempt without a proof: logged with the verifier check', async () => {
    const before = await balance();
    const r = await post('/api/attempt/direct', { tool: 'send_payment', arguments: { recipient: NORTHWIND, amount: '1' }, handle: 'mallory' });
    expect(await balance()).toBe(before);
    expect(r.body.attempt).toMatchObject({ route: 'direct', result: 'rejected', verdict: 'caught', caughtBy: { layer: 'verifier', check: 'missing_proof' }, attempted: { envelope: null } });
  });

  it('an anonymous visitor is a pseudonym, never an address; an unacceptable handle falls back to it', async () => {
    const r = await post('/api/attempt/enroll', { stage: 'options', handle: '<img src=x>' });
    expect(r.body.attempt.who).toMatch(/^anon-[0-9a-f]{6}$/);
    expect(r.body.attempt.who).toBe((await get('/api/whoami')).body.who);
    expect(r.body.attempt.caughtBy).toEqual({ layer: 'passkey-registry', check: 'owner_already_enrolled' });
  });

  it('the stats and the leaderboard reflect the attempts', async () => {
    const { body } = await get('/api/leaderboard');
    const row = (who: string) => body.leaderboard.find((r: { who: string }) => r.who === who);
    expect(row('alice')).toMatchObject({ attempts: 1, distinctChecks: 0, breaks: 0 });
    expect(row('mallory')).toMatchObject({ attempts: 2, distinctChecks: 2, breaks: 0 });
    expect(body.stats.byVerdict.break).toBe(0);
    const checks = Object.fromEntries(body.stats.byCheck.map((c: { layer: string; check: string; count: number }) => [`${c.layer}:${c.check}`, c.count]));
    expect(checks).toMatchObject({ 'firewall:recipient_not_allowlisted': 1, 'verifier:missing_proof': 1, 'passkey-registry:owner_already_enrolled': 1 });
    const filtered = (await get('/api/log?who=mallory&layer=verifier')).body.attempts;
    expect(filtered).toHaveLength(1);
  });

  it('rate-limits per client with 429 and Retry-After, and does not log refused requests', async () => {
    const total = async () => (await get('/api/status')).body.log.total as number;
    const before = await total();
    const codes: number[] = [];
    let retryAfter: string | null = null;
    for (let i = 0; i < 6; i++) {
      const r = await post('/api/attempt/direct', { tool: 'get_balance' });
      codes.push(r.status);
      if (r.status === 429) retryAfter = r.headers.get('retry-after');
    }
    // The direct bucket holds 4 and one direct attempt was made earlier.
    expect(codes).toEqual([200, 200, 200, 429, 429, 429]);
    expect(Number(retryAfter)).toBeGreaterThan(0);
    expect(await total()).toBe(before + 3);
  });

  it('persists every attempt, without addresses, and reloads them after a restart', async () => {
    const file = join(dataDir, 'attempts.jsonl');
    const lines = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const live = (await get('/api/status')).body.log.total;
    expect(lines).toHaveLength(live);
    const raw = readFileSync(file, 'utf8');
    expect(raw).not.toMatch(/127\.0\.0\.1|::1|::ffff/);
    expect(readdirSync(dataDir)).toEqual(['attempts.jsonl']);

    await svc.stop();
    svc = await start(dataDir);
    const after = await get('/api/status');
    expect(after.body.log.total).toBe(live);
    expect((await get('/api/log?who=alice')).body.attempts[0]).toEqual(lines.find((l) => l.who === 'alice'));
    // A new instance has a new policy and a fresh ledger; the log says which instance each attempt hit.
    expect(after.body.engine.policy.policyCommitment).not.toBe(lines[0].policyCommitment);
    expect(after.body.engine.ledger.treasury.balance).toBe('10000000000');
  });
});
