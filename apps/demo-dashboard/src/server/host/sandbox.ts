/**
 * Starts the agent in its own process under Node's permission model (`--permission`).
 *
 * What the agent process can do:
 *   - read its own code (src/agent, src/ipc, src/shared) and installed packages (node_modules);
 *   - talk to the firewall over its IPC channel.
 * What it cannot do: read any other file (the repository, the user's home directory, the
 * browser profile), write any file, open a network connection (so it cannot reach the
 * dashboard's HTTP API or the tool server), start processes or worker threads, load addons, or
 * attach an inspector. Its environment is empty apart from what is listed here.
 *
 * The policy opening exists in the browser's storage and in the firewall's memory. Neither is
 * reachable from inside this sandbox: the only thing the agent can do is send MCP requests to the
 * firewall, which answers with tool results and opaque refusals.
 */
import { type ChildProcess, fork } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const REPO_ROOT = resolve(APP_ROOT, '../..');

export const AGENT_ENTRY = resolve(APP_ROOT, 'src/agent/main.ts');

/** Paths the sandboxed process may read, besides its entry file. */
export const SANDBOX_READ_PATHS: readonly string[] = [
  resolve(APP_ROOT, 'src/agent'),
  resolve(APP_ROOT, 'src/ipc'),
  resolve(APP_ROOT, 'src/shared'),
  resolve(APP_ROOT, 'package.json'),
  resolve(APP_ROOT, 'node_modules'),
  resolve(REPO_ROOT, 'node_modules'),
];

/** Node flags of the sandbox. With `--permission`, everything not granted here is denied. */
export function sandboxExecArgv(entry: string): string[] {
  return ['--permission', ...[entry, ...SANDBOX_READ_PATHS].map((p) => `--allow-fs-read=${p}`)];
}

/** The agent's entire environment. */
export const SANDBOX_ENV: Readonly<Record<string, string>> = Object.freeze({ NODE_NO_WARNINGS: '1' });

export interface SandboxedProcess {
  readonly child: ChildProcess;
  /** stdout and stderr of the process, for debugging. */
  readonly output: () => string;
}

export function spawnSandboxed(entry: string, args: readonly string[] = []): SandboxedProcess {
  const child = fork(entry, [...args], {
    execArgv: sandboxExecArgv(entry),
    env: { ...SANDBOX_ENV },
    cwd: dirname(entry),
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    serialization: 'json',
  });
  let out = '';
  const keep = (b: Buffer) => {
    out = (out + b.toString('utf8')).slice(-20_000);
  };
  child.stdout?.on('data', keep);
  child.stderr?.on('data', keep);
  return { child, output: () => out };
}
