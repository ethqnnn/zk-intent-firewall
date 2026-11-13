/**
 * The treasury tool server as a child process of the host, reached only over IPC: an MCP client
 * for the firewall's upstream calls, and an RPC client for the registry operations the dashboard
 * asks the host to relay.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import type { CommitmentStatus, PolicyRegistry } from '@zk-intent-firewall/mcp-firewall';
import { fieldToHex } from '@zk-intent-firewall/mcp-firewall';
import { type ChildProcess, fork } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { VerifierLogEntry } from '../../shared/api.ts';
import { IpcMcpTransport, IpcRpcClient, isIpcMessage } from '../../ipc/channel.ts';
import type { VerifierConfig } from '../verifier/party.ts';

const ENTRY = resolve(dirname(fileURLToPath(import.meta.url)), '../verifier/main.ts');

export interface WireTap {
  /** Every MCP message and RPC call the host sends to a child, and every MCP message it receives. */
  (channel: 'agent' | 'tool-server', direction: 'in' | 'out', message: JSONRPCMessage | { rpc: string; params: unknown }): void;
}

export interface ToolServerProcessOptions {
  readonly onEvent: (entry: VerifierLogEntry) => void;
  readonly wireTap?: WireTap;
  /** Inherit stdout and stderr, for debugging. */
  readonly inheritOutput?: boolean;
}

export class ToolServerProcess {
  readonly child: ChildProcess;
  readonly client: Client;
  readonly rpc: IpcRpcClient;

  private constructor(child: ChildProcess, client: Client, rpc: IpcRpcClient) {
    this.child = child;
    this.client = client;
    this.rpc = rpc;
  }

  static async start(config: VerifierConfig, o: ToolServerProcessOptions): Promise<ToolServerProcess> {
    const child = fork(ENTRY, [], {
      stdio: ['ignore', o.inheritOutput ? 'inherit' : 'pipe', o.inheritOutput ? 'inherit' : 'pipe', 'ipc'],
      serialization: 'json',
    });
    let output = '';
    for (const s of [child.stdout, child.stderr]) s?.on('data', (b: Buffer) => (output = (output + b.toString()).slice(-20_000)));

    const ready = new Promise<void>((resolveReady, rejectReady) => {
      child.on('message', (m) => {
        if (!isIpcMessage(m) || m.kind !== 'event') return;
        const ev = m.event as { type?: string; entry?: VerifierLogEntry };
        if (ev.type === 'ready') resolveReady();
        else if (ev.type === 'verifier' && ev.entry) o.onEvent(ev.entry);
      });
      child.once('exit', (code) => rejectReady(new Error(`tool server exited with ${code} before it was ready:\n${output}`)));
    });
    await ready;

    const tap = o.wireTap;
    const rpc = new IpcRpcClient(child, tap ? { tap: (method, params) => tap('tool-server', 'out', { rpc: method, params }) } : {});
    await rpc.call('init', config);

    const client = new Client({ name: 'zk-intent-firewall-upstream', version: '0.1.0' });
    await client.connect(new IpcMcpTransport(child, tap ? { tap: (dir, msg) => tap('tool-server', dir, msg) } : {}));
    return new ToolServerProcess(child, client, rpc);
  }

  /** The verifier's registry as a PolicyRegistry, for the firewall to consult before proving. */
  remoteRegistry(): PolicyRegistry {
    return {
      status: async (commitment: bigint) => this.rpc.call<CommitmentStatus>('policy.status', { policyCommitment: fieldToHex(commitment) }),
    };
  }

  async stop(): Promise<void> {
    await this.client.close().catch(() => undefined);
    if (this.child.exitCode === null) {
      const exited = new Promise((r) => this.child.once('exit', r));
      if (this.child.connected) this.child.disconnect();
      const timer = setTimeout(() => this.child.kill('SIGKILL'), 5000);
      await exited;
      clearTimeout(timer);
    }
  }
}
