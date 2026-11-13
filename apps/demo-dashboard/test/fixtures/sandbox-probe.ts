/**
 * Runs inside the agent's sandbox (or, as a control, without it) and tries everything an agent
 * process would need to get at the policy opening or around the firewall. Reports each outcome
 * over IPC: 'allowed' or the error code.
 */
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { Worker } from 'node:worker_threads';

const target = JSON.parse(process.argv[2] ?? '{}') as { repoFile: string; port: number };
const out: Record<string, string> = {};
const attempt = (name: string, f: () => unknown) => {
  try {
    f();
    out[name] = 'allowed';
  } catch (e) {
    out[name] = (e as { code?: string }).code ?? (e as Error).message;
  }
};

attempt('read repository file', () => readFileSync(target.repoFile));
attempt('read /etc/passwd', () => readFileSync('/etc/passwd'));
attempt('list home directory', () => readdirSync(homedir()));
attempt('write a file', () => writeFileSync(`${tmpdir()}/zkif-sandbox-probe.txt`, 'x'));
attempt('spawn a process', () => {
  const r = spawnSync('/bin/sh', ['-c', 'true']);
  if (r.error) throw r.error;
});
attempt('start a worker', () => new Worker('1', { eval: true }).terminate());
out['open a TCP connection'] = await new Promise<string>((resolve) => {
  try {
    const s = connect(target.port, '127.0.0.1', () => {
      s.destroy();
      resolve('allowed');
    });
    s.on('error', (e: NodeJS.ErrnoException) => resolve(e.code ?? e.message));
  } catch (e) {
    resolve((e as { code?: string }).code ?? (e as Error).message);
  }
});
out['fetch over HTTP'] = await fetch(`http://127.0.0.1:${target.port}/`).then(
  () => 'allowed',
  (e: Error & { cause?: { code?: string } }) => e.cause?.code ?? (e as { code?: string }).code ?? e.message,
);
out['environment'] = Object.keys(process.env).sort().join(',');

process.send?.(out, () => process.disconnect?.());
