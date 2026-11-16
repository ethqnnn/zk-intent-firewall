/**
 * Configuration of the front process, from environment variables. Every limit has a default that
 * suits one small instance; the README lists them.
 */
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { ClientIpSource } from './client.ts';

export interface Limit {
  /** Requests a client can make at once. */
  readonly burst: number;
  /** Sustained requests per minute. */
  readonly perMinute: number;
}

export interface GateConfig {
  readonly concurrency: number;
  readonly queue: number;
}

export interface FrontConfig {
  readonly host: string;
  readonly port: number;
  /** Public origin of the page: the WebAuthn origin and RP ID, and the tool server's identity. */
  readonly origin: string;
  /** Where the attempt log is persisted. Unset: memory only. */
  readonly dataDir?: string;
  readonly crsPath: string;
  readonly proverThreads: number;
  readonly autoTopUp: boolean;
  readonly engineMaxOldSpaceMb: number;
  readonly clientIpSource: ClientIpSource;
  readonly proxyHops: number;
  readonly limits: {
    /** Attempts through the firewall (each may prove). */
    readonly agent: Limit;
    /** Attempts against the tool server directly (each may verify). */
    readonly direct: Limit;
    /** Passkey challenges, approvals and enrolment. */
    readonly passkey: Limit;
    /** Reads of the status, log and leaderboard. */
    readonly read: Limit;
    /** Across all clients: requests that may need a proof. */
    readonly globalProving: Limit;
  };
  readonly gates: { readonly agent: GateConfig; readonly direct: GateConfig; readonly passkey: GateConfig };
}

function int(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer from ${min} to ${max}`);
  return n;
}

function limit(env: NodeJS.ProcessEnv, name: string, burst: number, perMinute: number): Limit {
  return { burst: int(env, `${name}_BURST`, burst, 1, 100_000), perMinute: int(env, `${name}_PER_MINUTE`, perMinute, 1, 100_000) };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): FrontConfig {
  const port = int(env, 'PORT', 8080, 1, 65_535);
  const railwayDomain = env['RAILWAY_PUBLIC_DOMAIN'];
  const origin = new URL(env['BREAKIT_PUBLIC_ORIGIN'] || (railwayDomain ? `https://${railwayDomain}` : `http://localhost:${port}`)).origin;
  const source = (env['BREAKIT_CLIENT_IP_SOURCE'] || (env['RAILWAY_ENVIRONMENT'] || env['RAILWAY_PUBLIC_DOMAIN'] ? 'x-forwarded-for' : 'socket')) as ClientIpSource;
  if (!['socket', 'x-forwarded-for', 'x-real-ip'].includes(source)) throw new Error('BREAKIT_CLIENT_IP_SOURCE must be socket, x-forwarded-for or x-real-ip');
  const dataDir = env['BREAKIT_DATA_DIR'] || env['RAILWAY_VOLUME_MOUNT_PATH'] || undefined;
  return {
    host: env['HOST'] || '0.0.0.0',
    port,
    origin,
    ...(dataDir ? { dataDir } : {}),
    crsPath: env['BREAKIT_CRS_PATH'] || join(homedir(), '.bb-crs'),
    proverThreads: int(env, 'BREAKIT_PROVER_THREADS', 2, 1, 16),
    autoTopUp: env['BREAKIT_AUTO_TOP_UP'] !== '0',
    engineMaxOldSpaceMb: int(env, 'BREAKIT_ENGINE_MAX_OLD_SPACE_MB', 1536, 256, 16_384),
    clientIpSource: source,
    proxyHops: int(env, 'BREAKIT_PROXY_HOPS', 1, 1, 10),
    limits: {
      agent: limit(env, 'BREAKIT_LIMIT_AGENT', 6, 6),
      direct: limit(env, 'BREAKIT_LIMIT_DIRECT', 20, 20),
      passkey: limit(env, 'BREAKIT_LIMIT_PASSKEY', 10, 10),
      read: limit(env, 'BREAKIT_LIMIT_READ', 120, 120),
      globalProving: limit(env, 'BREAKIT_LIMIT_GLOBAL_PROVING', 20, 30),
    },
    gates: {
      agent: { concurrency: int(env, 'BREAKIT_GATE_AGENT_CONCURRENCY', 2, 1, 64), queue: int(env, 'BREAKIT_GATE_AGENT_QUEUE', 6, 0, 1000) },
      direct: { concurrency: int(env, 'BREAKIT_GATE_DIRECT_CONCURRENCY', 4, 1, 64), queue: int(env, 'BREAKIT_GATE_DIRECT_QUEUE', 16, 0, 1000) },
      passkey: { concurrency: 4, queue: 16 },
    },
  };
}
