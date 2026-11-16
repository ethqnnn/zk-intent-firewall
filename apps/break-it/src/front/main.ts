/**
 * Entry of the break-it service. Starts the sandboxed engine, checks that its sandbox holds,
 * opens the attempt log, and serves the page and the API.
 *
 *   node src/front/main.ts
 *
 * Configuration is by environment variable (front/config.ts, and the README).
 */
import { mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AttemptLog } from './attempt-log.ts';
import { loadConfig } from './config.ts';
import { EngineProcess, sandboxHolds } from './engine-process.ts';
import { createFront } from './http.ts';

const STATIC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../public');

const config = loadConfig();
const say = (m: string) => console.log(`[break-it] ${m}`);

say(`starting the engine for ${config.origin} (reference string in ${config.crsPath})`);
const engine = await EngineProcess.start({
  origin: config.origin,
  crsPath: config.crsPath,
  proverThreads: config.proverThreads,
  autoTopUp: config.autoTopUp,
  maxOldSpaceMb: config.engineMaxOldSpaceMb,
  inheritOutput: process.env['BREAKIT_DEBUG'] === '1',
});
say(`policy in force: ${engine.policyCommitment}`);

const sandbox = await engine.call<Record<string, string>>('sandbox.probe', {}, 15_000);
if (!sandboxHolds(sandbox)) {
  console.error('[break-it] the engine sandbox does not hold; refusing to serve:', sandbox);
  await engine.stop();
  process.exit(1);
}
say(`engine sandbox holds: ${JSON.stringify(sandbox)}`);

let logFile: string | undefined;
if (config.dataDir) {
  mkdirSync(config.dataDir, { recursive: true });
  logFile = join(config.dataDir, 'attempts.jsonl');
}
const log = await AttemptLog.open(logFile ? { file: logFile } : {});
say(logFile ? `attempt log: ${logFile} (${log.stats().total} earlier attempts loaded)` : 'attempt log: memory only (set BREAKIT_DATA_DIR or attach a volume to keep it)');

const server = createServer(createFront({ config, engine, log, staticDir: STATIC_DIR, sandbox }));
server.requestTimeout = 90_000;
server.headersTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.maxConnections = 1024;
server.maxRequestsPerSocket = 100;

let stopping = false;
engine.child.once('exit', (code, signal) => {
  if (stopping) return;
  console.error(`[break-it] the engine exited (${code ?? signal}); stopping so the platform restarts the service.\n${engine.output.slice(-4000)}`);
  process.exit(1);
});

const shutdown = () => {
  stopping = true;
  say('shutting down');
  server.close();
  void Promise.allSettled([engine.stop(), log.close()]).then(() => process.exit(0));
};
process.once('SIGTERM', shutdown);
process.once('SIGINT', shutdown);

server.listen(config.port, config.host, () => say(`listening on ${config.host}:${config.port}; open ${config.origin}`));
