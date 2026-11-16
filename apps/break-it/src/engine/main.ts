/**
 * Process entry of the engine. The front process forks it under Node's permission model with no
 * network, no child processes and no file writes except the reference-string cache (see
 * front/engine-process.ts). Its only interface is the IPC channel: RPC calls in, answers out.
 */
import { emitEvent, serveRpc } from '@zk-intent-firewall/demo-dashboard/src/ipc/channel.ts';
import { BreakItEngine } from './engine.ts';

if (typeof process.send !== 'function') {
  console.error('the engine must be started by the front process, with an IPC channel');
  process.exit(2);
}

const origin = process.env['BREAKIT_ORIGIN'];
if (!origin) {
  console.error('BREAKIT_ORIGIN is required');
  process.exit(2);
}
const crsPath = process.env['BREAKIT_CRS_PATH'];
const threads = Number(process.env['BREAKIT_PROVER_THREADS'] ?? '2');

const engine = await BreakItEngine.create({
  origin,
  ...(crsPath ? { crsPath } : {}),
  proverThreads: Number.isInteger(threads) && threads > 0 && threads <= 16 ? threads : 2,
  autoTopUp: process.env['BREAKIT_AUTO_TOP_UP'] !== '0',
});

interface Call {
  readonly client?: unknown;
  readonly body?: unknown;
}

const client = (p: unknown) => {
  const c = (p as Call | null)?.client;
  if (typeof c !== 'string' || c.length === 0 || c.length > 64) throw new Error('client key required');
  return c;
};

serveRpc(process, {
  status: () => engine.status(),
  'attempt.agent': (p) => engine.attemptAgent(client(p), (p as Call).body),
  'attempt.direct': (p) => engine.attemptDirect(client(p), (p as Call).body),
  'attempt.passkey': (p) => engine.attemptPasskey(client(p), (p as Call).body),
  'attempt.enroll': (p) => engine.attemptEnroll(client(p), (p as Call).body),
  'passkey.challenge': (p) => engine.passkeyChallenge((p as Call).body),
  // The front calls this once at boot and refuses to serve unless every probe was denied.
  'sandbox.probe': () => probeSandbox(),
});

process.on('disconnect', () => {
  void engine.destroy().finally(() => process.exit(0));
});

emitEvent(process, { type: 'ready', policyCommitment: engine.policyCommitment });

/**
 * Tries an outbound connection, a child process, a file write and a file read outside the allowed
 * paths, and reports the error code of each. Under the sandbox every one is ERR_ACCESS_DENIED.
 * The network probes target 192.0.2.1 (TEST-NET-1, RFC 5737, never routed), so even a broken
 * sandbox sends nothing anywhere real. Takes no input.
 */
async function probeSandbox(): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const code = (e: unknown) => String((e as { code?: unknown }).code ?? (e as { cause?: { code?: unknown } }).cause?.code ?? (e as Error).message);
  try {
    const net = await import('node:net');
    await new Promise<void>((resolve, reject) => {
      const s = net.connect({ host: '192.0.2.1', port: 443 }, () => {
        s.destroy();
        resolve();
      });
      s.on('error', reject);
      setTimeout(() => (s.destroy(), reject(Object.assign(new Error('timeout'), { code: 'TIMEOUT' }))), 1000);
    });
    out['network'] = 'ALLOWED';
  } catch (e) {
    out['network'] = code(e);
  }
  try {
    await fetch('http://192.0.2.1/', { signal: AbortSignal.timeout(1000) });
    out['fetch'] = 'ALLOWED';
  } catch (e) {
    out['fetch'] = code(e);
  }
  try {
    const cp = await import('node:child_process');
    cp.execFileSync('true');
    out['childProcess'] = 'ALLOWED';
  } catch (e) {
    out['childProcess'] = code(e);
  }
  try {
    const fs = await import('node:fs');
    fs.writeFileSync('/tmp/break-it-sandbox-probe', 'x');
    out['fileWrite'] = 'ALLOWED';
  } catch (e) {
    out['fileWrite'] = code(e);
  }
  try {
    const fs = await import('node:fs');
    fs.readFileSync('/etc/passwd');
    out['fileReadOutside'] = 'ALLOWED';
  } catch (e) {
    out['fileReadOutside'] = code(e);
  }
  out['env'] = Object.keys(process.env).sort().join(',');
  return out;
}
