/**
 * Process entry of the treasury tool server. Started by the host with an IPC channel, which is
 * its only interface: MCP for tool calls (from the firewall), RPC for registry operations (relayed
 * from the dashboard), and events for the audit log. stdout and stderr are logs only.
 */
import { emitEvent, IpcMcpTransport, serveRpc } from '../../ipc/channel.ts';
import type { VerifierConfig } from './party.ts';
import { VerifierParty } from './party.ts';

if (typeof process.send !== 'function') {
  console.error('the tool server must be started by the host, with an IPC channel');
  process.exit(2);
}

let party: VerifierParty | undefined;
let rpcReady = false;

serveRpc(process, {
  init: async (config: unknown) => {
    if (party) throw new Error('already initialised');
    const c = config as VerifierConfig;
    party = await VerifierParty.create({ ...c, onEvent: (entry) => emitEvent(process, { type: 'verifier', entry }) });
    await party.treasury.createServer().connect(new IpcMcpTransport(process));
    rpcReady = true;
    return { ok: true };
  },
  // Every other method is forwarded to the party once it exists.
  ...Object.fromEntries(
    ['enroll.options', 'enroll.complete', 'approval.issue', 'policy.register', 'policy.revoke', 'policy.records', 'policy.status', 'verifier.info', 'ledger'].map((m) => [
      m,
      (p: unknown) => {
        if (!party || !rpcReady) throw new Error('not initialised');
        return (party.rpcHandlers() as Record<string, (p: unknown) => unknown>)[m]!(p);
      },
    ]),
  ),
});

process.on('disconnect', () => {
  void (async () => {
    await party?.destroy().catch(() => undefined);
    process.exit(0);
  })();
});

emitEvent(process, { type: 'ready' });
