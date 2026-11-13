/**
 * Process entry of the agent. The host starts it inside Node's permission model (see
 * server/host/sandbox.ts): it can read its own code and nothing else, and has no network, no child
 * processes and no worker threads. Its only channel is the IPC pipe to the firewall: MCP for tool
 * calls, and events for its own transcript.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { emitEvent, IpcMcpTransport, isIpcMessage } from '../ipc/channel.ts';
import { CALL_ID_META } from '../shared/call-id.ts';
import { runScriptedAgent } from './scripted-agent.ts';

if (typeof process.send !== 'function') {
  console.error('the agent must be started by the host, with an IPC channel');
  process.exit(2);
}

const arg = (name: string) => process.argv.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);
const paceMs = Number(arg('pace') ?? '0');
const instruction = arg('instruction') ?? 'Process the accounts-payable inbox.';

// Wait for the host to have its firewall listening, then connect.
await new Promise<void>((resolve) => {
  const onMessage = (m: unknown) => {
    if (isIpcMessage(m) && m.kind === 'event' && (m.event as { type?: unknown })?.type === 'start') {
      process.off('message', onMessage);
      resolve();
    }
  };
  process.on('message', onMessage);
  emitEvent(process, { type: 'ready' });
});

const client = new Client({ name: 'ap-agent', version: '1.0.0' });
await client.connect(new IpcMcpTransport(process));

await runScriptedAgent(
  {
    async callTool(name, args, callId) {
      const r = (await client.callTool({ name, arguments: args, _meta: { [CALL_ID_META]: callId } })) as CallToolResult;
      const first = r.content[0];
      return { isError: r.isError === true, text: first?.type === 'text' ? first.text : '' };
    },
    emit: (step) => emitEvent(process, { type: 'agent', step }),
    sleep: (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms))),
  },
  instruction,
  Number.isFinite(paceMs) ? paceMs : 0,
);

await client.close();
process.disconnect?.();
