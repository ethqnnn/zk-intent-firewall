/**
 * Where the policy opening can and cannot go.
 *
 *   - The agent runs in a sandbox that cannot read files, open connections or start processes.
 *   - No message to or from the agent, and none to the tool server, carries any policy value.
 *   - Neither does the audit log, the event stream, or any GET endpoint of the dashboard API.
 *   - The dashboard API refuses requests without the session token, from another origin, or
 *     without a JSON body.
 */
import { fieldToHex, getHasher, PolicyOpening, recipientId } from '@zk-intent-firewall/mcp-firewall';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { setUpDemo } from '../src/demo/flow.ts';
import type { SoftAuthenticator } from '../src/demo/soft-authenticator.ts';
import type { Host } from '../src/server/host/host.ts';
import { createRequestHandler } from '../src/server/host/http.ts';
import { SANDBOX_ENV, spawnSandboxed } from '../src/server/host/sandbox.ts';
import { SESSION_HEADER } from '../src/shared/api.ts';
import { PAYEES, USDC_ASSET_ID } from '../src/shared/demo-config.ts';
import { startHost, type Wire } from './helpers.ts';

const PROBE = fileURLToPath(new URL('./fixtures/sandbox-probe.ts', import.meta.url));
const REPO_FILE = fileURLToPath(new URL('../../../packages/zk-circuit/fixtures/vk_hashes.txt', import.meta.url));

async function probe(sandboxed: boolean): Promise<Record<string, string>> {
  const tcp = createTcpServer((s) => s.destroy());
  tcp.listen(0, '127.0.0.1');
  await once(tcp, 'listening');
  const port = (tcp.address() as { port: number }).port;
  const arg = JSON.stringify({ repoFile: REPO_FILE, port });
  const child = sandboxed
    ? spawnSandboxed(PROBE, [arg]).child
    : fork(PROBE, [arg], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'], serialization: 'json', env: { ...process.env, ZKIF_PROBE_CONTROL: '1' } });
  let output = '';
  child.stdout?.on('data', (b: Buffer) => (output += b.toString()));
  child.stderr?.on('data', (b: Buffer) => (output += b.toString()));
  try {
    // Fail fast if the probe dies instead of reporting.
    return await new Promise<Record<string, string>>((resolveReport, reject) => {
      child.once('message', (m) => resolveReport(m as Record<string, string>));
      child.once('exit', (code) => reject(new Error(`probe exited with ${code} without reporting:\n${output}`)));
    });
  } finally {
    child.kill();
    tcp.close();
  }
}

describe('agent sandbox', () => {
  it('the probe detects access when it is not sandboxed (control)', async () => {
    const r = await probe(false);
    for (const k of ['read repository file', 'read /etc/passwd', 'list home directory', 'write a file', 'spawn a process', 'start a worker', 'open a TCP connection']) {
      expect(r[k], k).toBe('allowed');
    }
    expect(r['environment']).toContain('ZKIF_PROBE_CONTROL');
  });

  it('denies file access outside its own code, writes, processes, workers and the network', async () => {
    const r = await probe(true);
    for (const k of ['read repository file', 'read /etc/passwd', 'list home directory', 'write a file', 'spawn a process', 'start a worker', 'open a TCP connection']) {
      expect(r[k], k).toBe('ERR_ACCESS_DENIED');
    }
    expect(r['fetch over HTTP']).not.toBe('allowed');
    // Nothing from the parent's environment (tokens, paths, credentials) is inherited.
    expect(r['environment']).toBe(Object.keys(SANDBOX_ENV).sort().join(','));
  });
});

describe('no policy value leaves the browser and the firewall', () => {
  let host: Host;
  let auth: SoftAuthenticator;
  let wire: Wire;
  const events: string[] = [];
  let secrets: Record<string, string[]>;
  let openingJson: string;
  let commitment: string;
  let http: Server;
  let base: string;

  beforeAll(async () => {
    ({ host, auth, wire } = await startHost());
    host.subscribe((e) => events.push(JSON.stringify(e)));
    const { policy } = await setUpDemo(host, auth);
    commitment = policy.policyCommitment;
    await host.runDemo();
    await host.runDemo({ firewallChecksRegistry: false });

    openingJson = JSON.stringify({ opening: policy.opening });
    const opening = PolicyOpening.fromJSON(await getHasher(), policy.opening as never);
    const litware = recipientId(USDC_ASSET_ID, PAYEES.litware.account);
    const forms = (x: bigint) => [fieldToHex(x).slice(2), x.toString(10)];
    secrets = {
      salt: forms(opening.fields.salt),
      allowlistRoot: forms(opening.fields.allowlistRoot),
      maxAmount: [opening.fields.maxAmount.toString(10)],
      expiry: [opening.fields.expiry.toString(10)],
      // Allowlisted, but never paid and never mentioned in the inbox: nothing should reveal it.
      litwareAccount: [PAYEES.litware.account.split(':')[2]!.slice(2)],
      litwareRecipientId: forms(litware),
      litwareName: ['Litware', 'litware'],
      openingFields: ['"salt"', '"maxAmount"', '"max_amount"', '"allowlistRoot"', '"allowlist_root"', '"scopeMask"', '"scope_mask"', '"expiry"', '"recipients"', '"opening"'],
    };

    http = createHttpServer(createRequestHandler(host));
    http.listen(0, '127.0.0.1');
    await once(http, 'listening');
    base = `http://127.0.0.1:${(http.address() as { port: number }).port}`;
  });

  afterAll(async () => {
    http?.close();
    await host?.stop();
  });

  const leaks = (haystack: readonly string[]) => {
    const found: string[] = [];
    for (const [name, needles] of Object.entries(secrets)) for (const n of needles) if (haystack.some((h) => h.includes(n))) found.push(`${name} (${n.slice(0, 16)})`);
    return found;
  };

  it('the search terms match the opening as it is encoded (control)', () => {
    // If the terms were in the wrong form the scan below would prove nothing.
    const found = leaks([openingJson]);
    for (const name of ['salt', 'maxAmount', 'expiry', 'litwareRecipientId', 'openingFields']) expect(found.some((f) => f.startsWith(name)), name).toBe(true);
  });

  it('the scan sees real traffic', () => {
    expect(wire.toAgent.length).toBeGreaterThan(10);
    expect(wire.fromAgent.length).toBeGreaterThan(10);
    expect(wire.toToolServer.some((m) => m.includes(commitment.slice(2)))).toBe(true);
    expect(wire.fromToolServer.length).toBeGreaterThan(5);
  });

  it('agent channel: nothing in either direction', () => {
    expect(leaks(wire.toAgent)).toEqual([]);
    expect(leaks(wire.fromAgent)).toEqual([]);
  });

  it('tool-server channel: no MCP request, RPC or response carries a policy value', () => {
    expect(leaks(wire.toToolServer)).toEqual([]);
    expect(leaks(wire.fromToolServer)).toEqual([]);
  });

  it('audit log and event stream: none either', async () => {
    expect(leaks([JSON.stringify(await host.log())])).toEqual([]);
    expect(events.length).toBeGreaterThan(20);
    expect(leaks(events)).toEqual([]);
  });

  it('no GET endpoint returns any of it, even while armed', async () => {
    expect(host.firewall.armedCommitment).toBe(commitment);
    for (const path of ['/api/state', '/api/log', '/api/inbox']) {
      const r = await fetch(base + path, { headers: { [SESSION_HEADER]: host.sessionToken } });
      expect(r.status, path).toBe(200);
      expect(leaks([await r.text()]), path).toEqual([]);
    }
  });

  it('a policy needs a salt of at least 128 bits, drawn in the browser', async () => {
    const req = { maxAmount: '1000000', recipients: [PAYEES.fabrikam.account], scopes: ['payments.send'], expiry: '4102444800' };
    await expect(host.preparePolicy({ ...req, salt: '0x' + 'ff'.repeat(15) } as never)).rejects.toThrow(/128 bits/);
    await expect(host.preparePolicy({ ...req, salt: '0x0' } as never)).rejects.toThrow();
    await expect(host.preparePolicy({ ...req, salt: '0x01' + '00'.repeat(16) } as never)).resolves.toHaveProperty('policyCommitment');
  });

  describe('dashboard API guards', () => {
    const post = (path: string, init: { token?: string | null; origin?: string | null; type?: string; body?: string } = {}) => {
      const headers: Record<string, string> = {};
      const token = init.token === undefined ? host.sessionToken : init.token;
      if (token !== null) headers[SESSION_HEADER] = token;
      const origin = init.origin === undefined ? host.origin : init.origin;
      if (origin !== null) headers['origin'] = origin;
      headers['content-type'] = init.type ?? 'application/json';
      return fetch(base + path, { method: 'POST', headers, body: init.body ?? '{}' });
    };

    it('a valid request passes every guard (control)', async () => {
      expect((await post('/api/policies/records', { body: JSON.stringify({ commitments: [commitment] }) })).status).toBe(200);
    });

    it('no token or a wrong token: 401, on GET and POST', async () => {
      expect((await fetch(base + '/api/state')).status).toBe(401);
      expect((await fetch(base + '/api/log', { headers: { [SESSION_HEADER]: host.sessionToken.slice(0, -1) + 'x' } })).status).toBe(401);
      expect((await post('/api/firewall/disarm', { token: null })).status).toBe(401);
      expect((await post('/api/firewall/disarm', { token: 'x'.repeat(host.sessionToken.length) })).status).toBe(401);
    });

    it('another origin, or none: 403', async () => {
      expect((await post('/api/firewall/disarm', { origin: 'http://evil.example' })).status).toBe(403);
      expect((await post('/api/firewall/disarm', { origin: null })).status).toBe(403);
    });

    it('a non-JSON body (a form post, for example): 415', async () => {
      expect((await post('/api/firewall/disarm', { type: 'text/plain' })).status).toBe(415);
      expect((await post('/api/firewall/disarm', { type: 'application/x-www-form-urlencoded', body: 'a=1' })).status).toBe(415);
    });

    it('the guards stopped those requests: the firewall is still armed', () => {
      expect(host.firewall.armedCommitment).toBe(commitment);
    });
  });
});
