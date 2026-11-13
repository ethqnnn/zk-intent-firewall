/**
 * Starts the dashboard: the host (firewall and API), the tool server, and the web app.
 *
 *   node src/server/main.ts            serve the built app from dist/ (run `pnpm build` first)
 *   node src/server/main.ts --dev      serve the app through Vite, with hot reload
 *   --port=<n>                         default 5173
 *
 * Open the printed URL. It carries the session token in its fragment, which the browser keeps.
 */
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Host } from './host/host.ts';
import { createRequestHandler, type HttpOptions } from './host/http.ts';

const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const dev = process.argv.includes('--dev');
const port = Number(process.argv.find((a) => a.startsWith('--port='))?.slice(7) ?? process.env['ZKIF_PORT'] ?? 5173);

const server = createServer();
const server6 = createServer();
// WebAuthn needs a domain as RP ID, not an IP address; localhost is a secure context.
const origin = `http://localhost:${port}`;

const token = process.env['ZKIF_SESSION_TOKEN'];
const host = await Host.start({ origin, ...(token ? { sessionToken: token } : {}), inheritOutput: process.env['ZKIF_DEBUG'] === '1' });

let http: HttpOptions = { staticDir: resolve(APP_ROOT, 'dist') };
if (dev) {
  const { createServer: createVite } = await import('vite');
  const vite = await createVite({ root: APP_ROOT, server: { middlewareMode: true, hmr: { server } }, appType: 'spa' });
  http = { devMiddleware: (req, res, next) => vite.middlewares(req, res, next) };
}
const handle = createRequestHandler(host, http);
server.on('request', (req, res) => void handle(req, res));
server6.on('request', (req, res) => void handle(req, res));

// Listen only once requests have a handler: one accepted earlier would hang unanswered.
// Loopback only. `localhost` may resolve to ::1 or 127.0.0.1 first, so listen on both.
await new Promise<void>((r) => server.listen(port, '127.0.0.1', r));
await new Promise<void>((r) => {
  server6.once('error', () => r()); // no IPv6 loopback on this machine
  server6.listen(port, '::1', r);
});

console.log(`\nzk-intent-firewall dashboard${dev ? ' (dev)' : ''}`);
console.log(`  Open: ${origin}/#token=${host.sessionToken}`);
console.log('  The token is the key to this dashboard. Do not share the URL.\n');

const shutdown = async () => {
  server.close();
  server6.close();
  await host.stop();
  process.exit(0);
};
process.on('SIGINT', () => void shutdown());
process.on('SIGTERM', () => void shutdown());
