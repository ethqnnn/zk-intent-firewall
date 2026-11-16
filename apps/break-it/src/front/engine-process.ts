/**
 * Starts the engine in its own process under Node's permission model (`--permission`).
 *
 * The engine handles every attacker-controlled byte that matters: tool arguments, proof envelopes,
 * WebAuthn responses. So it gets as little as possible:
 *
 *   - read: its own code, the code it imports (packages/mcp-firewall, the dashboard modules it
 *     reuses), installed packages, and Barretenberg's reference-string cache;
 *   - write: the reference-string cache only (bb.js opens a lock file there);
 *   - worker threads, which bb.js needs for its WASM threads (workers inherit every restriction);
 *   - nothing else: no network at all, no child processes, no addons, no inspector, no WASI;
 *   - an environment of five variables, none secret.
 *
 * Node's network permission is all or nothing, so the process that listens for HTTP cannot be the
 * one that is denied the network. That is why there are two processes. The front process (this
 * one) parses HTTP, rate-limits and keeps the public log; the engine never sees a socket. At boot
 * the front asks the engine to try a connection, a fetch, a child process, a write and a read
 * outside its paths, and refuses to serve unless all five were denied.
 */
import { type ChildProcess, fork } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { IpcRpcClient, isIpcMessage } from '@zk-intent-firewall/demo-dashboard/src/ipc/channel.ts';

const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const REPO_ROOT = resolve(APP_ROOT, '../..');

export const ENGINE_ENTRY = resolve(APP_ROOT, 'src/engine/main.ts');

/** Paths the engine may read, besides the reference-string cache. */
export const ENGINE_READ_PATHS: readonly string[] = [
  resolve(APP_ROOT, 'src/engine'),
  resolve(APP_ROOT, 'src/shared'),
  resolve(APP_ROOT, 'package.json'),
  resolve(APP_ROOT, 'node_modules'),
  resolve(REPO_ROOT, 'apps/demo-dashboard/src'),
  resolve(REPO_ROOT, 'apps/demo-dashboard/package.json'),
  resolve(REPO_ROOT, 'apps/demo-dashboard/node_modules'),
  resolve(REPO_ROOT, 'packages/mcp-firewall/dist'),
  resolve(REPO_ROOT, 'packages/mcp-firewall/circuit'),
  resolve(REPO_ROOT, 'packages/mcp-firewall/package.json'),
  resolve(REPO_ROOT, 'packages/mcp-firewall/node_modules'),
  resolve(REPO_ROOT, 'node_modules'),
  resolve(REPO_ROOT, 'package.json'),
];

export interface EngineProcessOptions {
  readonly origin: string;
  /** Barretenberg's reference-string cache. Must already hold the reference string. */
  readonly crsPath: string;
  readonly proverThreads: number;
  readonly autoTopUp: boolean;
  /** V8 heap cap of the engine, in MB. */
  readonly maxOldSpaceMb: number;
  readonly inheritOutput?: boolean;
}

export function engineExecArgv(o: Pick<EngineProcessOptions, 'crsPath' | 'maxOldSpaceMb'>): string[] {
  return [
    '--permission',
    ...[ENGINE_ENTRY, ...ENGINE_READ_PATHS, o.crsPath].map((p) => `--allow-fs-read=${p}`),
    `--allow-fs-write=${o.crsPath}`,
    '--allow-worker',
    `--max-old-space-size=${o.maxOldSpaceMb}`,
    '--disable-proto=throw',
  ];
}

export function engineEnv(o: EngineProcessOptions): Record<string, string> {
  return {
    NODE_NO_WARNINGS: '1',
    BREAKIT_ORIGIN: o.origin,
    BREAKIT_CRS_PATH: o.crsPath,
    BREAKIT_PROVER_THREADS: String(o.proverThreads),
    BREAKIT_AUTO_TOP_UP: o.autoTopUp ? '1' : '0',
  };
}

export class EngineProcess {
  readonly child: ChildProcess;
  readonly policyCommitment: string;
  readonly #rpc: IpcRpcClient;
  readonly #output: () => string;

  private constructor(child: ChildProcess, rpc: IpcRpcClient, policyCommitment: string, output: () => string) {
    this.child = child;
    this.#rpc = rpc;
    this.policyCommitment = policyCommitment;
    this.#output = output;
  }

  static async start(o: EngineProcessOptions): Promise<EngineProcess> {
    const child = fork(ENGINE_ENTRY, [], {
      execArgv: engineExecArgv(o),
      env: engineEnv(o),
      cwd: dirname(ENGINE_ENTRY),
      stdio: ['ignore', o.inheritOutput ? 'inherit' : 'pipe', o.inheritOutput ? 'inherit' : 'pipe', 'ipc'],
      serialization: 'json',
    });
    let output = '';
    for (const s of [child.stdout, child.stderr]) s?.on('data', (b: Buffer) => (output = (output + b.toString('utf8')).slice(-20_000)));
    const policyCommitment = await new Promise<string>((resolveReady, rejectReady) => {
      const onMessage = (m: unknown) => {
        if (!isIpcMessage(m) || m.kind !== 'event') return;
        const ev = m.event as { type?: string; policyCommitment?: string };
        if (ev.type === 'ready' && typeof ev.policyCommitment === 'string') {
          child.off('message', onMessage);
          resolveReady(ev.policyCommitment);
        }
      };
      child.on('message', onMessage);
      child.once('exit', (code) => rejectReady(new Error(`the engine exited with ${code} before it was ready:\n${output}`)));
    });
    return new EngineProcess(child, new IpcRpcClient(child), policyCommitment, () => output);
  }

  /** Calls an engine method, failing after `timeoutMs`. */
  call<T>(method: string, params: unknown, timeoutMs = 60_000): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`engine call ${method} timed out`)), timeoutMs);
    });
    return Promise.race([this.#rpc.call<T>(method, params), timeout]).finally(() => clearTimeout(timer));
  }

  get output(): string {
    return this.#output();
  }

  async stop(): Promise<void> {
    if (this.child.exitCode !== null || this.child.signalCode !== null) return;
    const exited = new Promise((r) => this.child.once('exit', r));
    if (this.child.connected) this.child.disconnect();
    const timer = setTimeout(() => this.child.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(timer);
  }
}

/** True when every sandbox probe was denied by the permission model. */
export function sandboxHolds(probe: Readonly<Record<string, string>>): boolean {
  return ['network', 'fetch', 'childProcess', 'fileWrite', 'fileReadOutside'].every((k) => probe[k] === 'ERR_ACCESS_DENIED');
}
