import { mkdtempSync, readFileSync, rmSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AttemptLog } from '../src/front/attempt-log.ts';
import type { AttemptRecord } from '../src/shared/types.ts';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'break-it-log-'));
  dirs.push(d);
  return join(d, 'attempts.jsonl');
};

let n = 0;
function rec(over: Partial<AttemptRecord> = {}): AttemptRecord {
  n += 1;
  return {
    id: `id-${n}`,
    at: new Date(1_800_000_000_000 + n * 1000).toISOString(),
    policyCommitment: `0x${'a'.repeat(64)}`,
    who: 'anon-000000',
    route: 'agent',
    attempted: { tool: 'send_payment', arguments: '{"amount":"1"}' },
    result: 'blocked',
    caughtBy: { layer: 'firewall', check: 'recipient_not_allowlisted' },
    verdict: 'caught',
    ms: 3,
    ...over,
  };
}

describe('attempt log', () => {
  it('records exactly what it was given, and lists most recent first', async () => {
    const log = await AttemptLog.open();
    const a = rec({ who: 'alice', note: 'lookalike' });
    const b = rec({ verdict: 'legitimate', result: 'executed', caughtBy: null, payment: { tool: 'send_payment', recipient: 'r', amount: '5', reference: 'fake-tx-1' } });
    log.add(a);
    log.add(b);
    expect(log.list()).toEqual([b, a]);
    expect(log.get(a.id)).toEqual(a);
  });

  it('counts by verdict, route and named check, and keeps every break', async () => {
    const log = await AttemptLog.open();
    log.add(rec());
    log.add(rec());
    log.add(rec({ route: 'direct', caughtBy: { layer: 'verifier', check: 'invalid_proof' } }));
    log.add(rec({ route: 'direct', caughtBy: { layer: 'verifier', check: 'replayed' } }));
    log.add(rec({ route: 'agent', verdict: 'legitimate', result: 'executed', caughtBy: null }));
    const brk = rec({ route: 'passkey', verdict: 'break', result: 'approved', caughtBy: null, breakReasons: ['revoke_approved_without_the_owner_key'] });
    log.add(brk);
    const s = log.stats();
    expect(s.total).toBe(6);
    expect(s.byVerdict).toEqual({ caught: 4, legitimate: 1, break: 1 });
    expect(s.byRoute).toEqual({ agent: 3, direct: 2, passkey: 1 });
    expect(s.byCheck).toEqual([
      { layer: 'firewall', check: 'recipient_not_allowlisted', count: 2 },
      { layer: 'verifier', check: 'invalid_proof', count: 1 },
      { layer: 'verifier', check: 'replayed', count: 1 },
    ]);
    expect(s.breaks).toEqual([brk]);
  });

  it('filters and pages', async () => {
    const log = await AttemptLog.open();
    const all = Array.from({ length: 10 }, (_, i) => rec({ who: i % 2 ? 'odd' : 'even', caughtBy: { layer: 'verifier', check: i < 5 ? 'replayed' : 'invalid_proof' } }));
    for (const r of all) log.add(r);
    expect(log.list({ limit: 3 }).map((r) => r.id)).toEqual([all[9]!.id, all[8]!.id, all[7]!.id]);
    expect(log.list({ limit: 3, before: all[7]!.id }).map((r) => r.id)).toEqual([all[6]!.id, all[5]!.id, all[4]!.id]);
    expect(log.list({ who: 'odd', check: 'replayed' }).map((r) => r.id)).toEqual([all[3]!.id, all[1]!.id]);
    expect(log.list({ layer: 'firewall' })).toEqual([]);
    expect(log.list({ limit: 10_000 })).toHaveLength(10);
  });

  it('ranks the leaderboard by breaks, then distinct checks probed, then attempts', async () => {
    const log = await AttemptLog.open();
    for (let i = 0; i < 5; i++) log.add(rec({ who: 'busy' }));
    log.add(rec({ who: 'broad', caughtBy: { layer: 'verifier', check: 'replayed' } }));
    log.add(rec({ who: 'broad', caughtBy: { layer: 'circuit', check: 'circuit_rejected' } }));
    log.add(rec({ who: 'lucky', verdict: 'break', caughtBy: null }));
    expect(log.leaderboard().map((r) => [r.who, r.attempts, r.distinctChecks, r.breaks])).toEqual([
      ['lucky', 1, 0, 1],
      ['broad', 2, 2, 0],
      ['busy', 5, 1, 0],
    ]);
  });

  it('persists every attempt as one JSON line and loads them back after a restart', async () => {
    const file = tmp();
    const first = await AttemptLog.open({ file });
    const a = rec({ who: 'alice' });
    const b = rec({ verdict: 'break', caughtBy: null });
    first.add(a);
    first.add(b);
    await first.close();
    expect(readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l))).toEqual([a, b]);

    // A torn line from a crash is skipped, not fatal.
    appendFileSync(file, '{"id":"torn');
    const second = await AttemptLog.open({ file });
    expect(second.list()).toEqual([b, a]);
    expect(second.stats()).toMatchObject({ total: 2, byVerdict: { caught: 1, legitimate: 0, break: 1 }, persisted: true });
    expect(second.stats().breaks).toEqual([b]);
    await second.close();
  });

  it('keeps a bounded window in memory but counts everything', async () => {
    const log = await AttemptLog.open({ keep: 3 });
    for (let i = 0; i < 10; i++) log.add(rec());
    expect(log.list({ limit: 100 })).toHaveLength(3);
    expect(log.stats().total).toBe(10);
  });

  it('stops appending at the size cap, and says so', async () => {
    const file = tmp();
    const log = await AttemptLog.open({ file, maxFileBytes: 600 });
    for (let i = 0; i < 10; i++) log.add(rec());
    expect(log.persisted).toBe(false);
    await log.close();
    expect(readFileSync(file, 'utf8').length).toBeLessThan(1200);
    expect(log.stats().total).toBe(10);
  });
});
