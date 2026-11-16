import type { IncomingMessage } from 'node:http';
import { describe, expect, it } from 'vitest';
import { ClientKeys, clientAddress, handleOf, pseudonym } from '../src/front/client.ts';
import { loadConfig } from '../src/front/config.ts';
import { Gate, RateLimiter } from '../src/front/limits.ts';

describe('rate limiter', () => {
  it('allows a burst, then refills at the configured rate, per key', () => {
    let t = 0;
    const l = new RateLimiter({ capacity: 3, refillPerSecond: 0.5, now: () => t });
    expect([l.take('a'), l.take('a'), l.take('a')].every((r) => r.ok)).toBe(true);
    expect(l.take('a')).toEqual({ ok: false, retryAfterSeconds: 2 });
    expect(l.take('b').ok).toBe(true);
    t = 2;
    expect(l.take('a').ok).toBe(true);
    expect(l.take('a').ok).toBe(false);
    t = 100;
    expect(l.remaining('a')).toBe(3);
  });

  it('a flood of distinct keys stays bounded', () => {
    const l = new RateLimiter({ capacity: 1, refillPerSecond: 0.001, maxKeys: 100, now: () => 0 });
    for (let i = 0; i < 1000; i++) l.take(`k${i}`);
    // Not observable directly; the point is that it neither throws nor grows without bound.
    expect(l.take('k999').ok).toBe(false);
  });
});

describe('gate', () => {
  it('runs up to its concurrency, queues up to its queue, and refuses the rest at once', async () => {
    const g = new Gate({ concurrency: 2, queue: 1 });
    const release: (() => void)[] = [];
    const task = () => new Promise<number>((r) => release.push(() => r(1)));
    const runs = [g.run(task), g.run(task), g.run(task)];
    expect(await g.run(task)).toBeUndefined();
    expect(g.load).toEqual({ running: 2, waiting: 1 });
    release.shift()!();
    await new Promise((r) => setTimeout(r, 0));
    expect(g.load).toEqual({ running: 2, waiting: 0 });
    while (release.length) release.shift()!();
    await new Promise((r) => setTimeout(r, 0));
    while (release.length) release.shift()!();
    expect(await Promise.all(runs)).toEqual([{ value: 1 }, { value: 1 }, { value: 1 }]);
    expect(g.load).toEqual({ running: 0, waiting: 0 });
  });

  it('frees its slot when a task throws', async () => {
    const g = new Gate({ concurrency: 1, queue: 0 });
    await expect(g.run(() => Promise.reject(new Error('x')))).rejects.toThrow('x');
    expect(await g.run(async () => 2)).toEqual({ value: 2 });
  });
});

describe('client identity', () => {
  const req = (headers: Record<string, string>, remoteAddress = '10.0.0.9') => ({ headers, socket: { remoteAddress } }) as unknown as IncomingMessage;

  it('takes the proxy-added entry of X-Forwarded-For, which a client cannot spoof', () => {
    expect(clientAddress(req({ 'x-forwarded-for': '6.6.6.6, 203.0.113.7' }), 'x-forwarded-for')).toBe('203.0.113.7');
    expect(clientAddress(req({ 'x-forwarded-for': '203.0.113.7' }), 'x-forwarded-for')).toBe('203.0.113.7');
    expect(clientAddress(req({ 'x-forwarded-for': '6.6.6.6, 203.0.113.7, 10.1.1.1' }), 'x-forwarded-for', 2)).toBe('203.0.113.7');
    expect(clientAddress(req({}), 'x-forwarded-for')).toBe('10.0.0.9');
    expect(clientAddress(req({ 'x-forwarded-for': '6.6.6.6' }), 'socket')).toBe('10.0.0.9');
    expect(clientAddress(req({ 'x-real-ip': '203.0.113.8' }), 'x-real-ip')).toBe('203.0.113.8');
  });

  it('keys are stable per address within a process, and unlinkable across processes', () => {
    const k1 = new ClientKeys();
    const k2 = new ClientKeys();
    expect(k1.key('203.0.113.7')).toBe(k1.key('203.0.113.7'));
    expect(k1.key('203.0.113.7')).not.toBe(k1.key('203.0.113.8'));
    expect(k1.key('203.0.113.7')).not.toBe(k2.key('203.0.113.7'));
    expect(pseudonym(k1.key('203.0.113.7'))).toMatch(/^anon-[0-9a-f]{6}$/);
    expect(k1.key('203.0.113.7')).not.toContain('203');
  });

  it('accepts plain handles only, and reserves anon-', () => {
    expect(handleOf('alice_01')).toBe('alice_01');
    expect(handleOf('anon-abcdef')).toBeUndefined();
    expect(handleOf('<script>')).toBeUndefined();
    expect(handleOf('a')).toBeUndefined();
    expect(handleOf('x'.repeat(25))).toBeUndefined();
    expect(handleOf(42)).toBeUndefined();
  });
});

describe('config', () => {
  it('defaults for a local run', () => {
    const c = loadConfig({});
    expect(c).toMatchObject({ port: 8080, origin: 'http://localhost:8080', clientIpSource: 'socket', proverThreads: 2, autoTopUp: true });
    expect(c.dataDir).toBeUndefined();
  });

  it('on Railway: the public domain is the origin, the client address comes from X-Forwarded-For, the volume keeps the log', () => {
    const c = loadConfig({ PORT: '3000', RAILWAY_PUBLIC_DOMAIN: 'break-it.up.railway.app', RAILWAY_ENVIRONMENT: 'production', RAILWAY_VOLUME_MOUNT_PATH: '/data' });
    expect(c).toMatchObject({ port: 3000, origin: 'https://break-it.up.railway.app', clientIpSource: 'x-forwarded-for', proxyHops: 1, dataDir: '/data' });
  });

  it('refuses nonsense', () => {
    expect(() => loadConfig({ BREAKIT_CLIENT_IP_SOURCE: 'cookie' })).toThrow();
    expect(() => loadConfig({ BREAKIT_PROVER_THREADS: '0' })).toThrow();
    expect(() => loadConfig({ BREAKIT_LIMIT_AGENT_PER_MINUTE: 'lots' })).toThrow();
  });
});
