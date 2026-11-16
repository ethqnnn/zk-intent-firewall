/**
 * Static guard: no source file of this package opens an outbound connection. Only two files may
 * touch the modules that could: the engine's sandbox probe (which must fail) and the launcher that
 * forks the engine. The runtime guarantee is the permission model (service.test.ts checks it);
 * this catches a careless import before it ships.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), '../src');
const PUBLIC = resolve(dirname(fileURLToPath(import.meta.url)), '../public');

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

const OUTBOUND = [/\bfetch\s*\(/, /\bnode:https?['"]/, /\bnode:net['"]/, /\bnode:tls['"]/, /\bnode:dgram['"]/, /\bnode:dns['"]/, /\bnode:child_process['"]/, /\bnode:worker_threads['"]/, /\bWebSocket\b/, /\bXMLHttpRequest\b/];
const ALLOWED: Record<string, RegExp[]> = {
  // The sandbox probe: every one of these must be denied at run time.
  'engine/main.ts': [/\bfetch\s*\(/, /\bnode:net['"]/, /\bnode:child_process['"]/],
  // Forks the engine.
  'front/engine-process.ts': [/\bnode:child_process['"]/],
  // Serves HTTP: imports node:http for its types and createServer only.
  'front/main.ts': [/\bnode:https?['"]/],
  'front/http.ts': [/\bnode:https?['"]/],
  'front/client.ts': [/\bnode:https?['"]/],
};

describe('no outbound network code', () => {
  it('in the server sources', () => {
    const offenders: string[] = [];
    for (const f of files(SRC)) {
      const rel = relative(SRC, f);
      const src = readFileSync(f, 'utf8');
      for (const re of OUTBOUND) if (re.test(src) && !(ALLOWED[rel] ?? []).some((a) => a.source === re.source)) offenders.push(`${rel}: ${re}`);
    }
    expect(offenders).toEqual([]);
  });

  it('in the pages: they only call their own origin, by relative path', () => {
    for (const f of files(PUBLIC).filter((p) => p.endsWith('.js') || p.endsWith('.html'))) {
      const src = readFileSync(f, 'utf8');
      for (const m of src.matchAll(/fetch\(\s*([`'"])([^`'"]*)/g)) expect(m[2], f).toMatch(/^\/api\//);
      expect(src, f).not.toMatch(/<script[^>]+src=["']https?:/);
      expect(src, f).not.toMatch(/innerHTML\s*=/);
    }
  });
});
