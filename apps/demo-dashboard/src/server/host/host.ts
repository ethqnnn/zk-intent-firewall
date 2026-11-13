/**
 * The host: the dashboard's backend and the firewall, in one process. It starts the tool server
 * and, for each demo run, a sandboxed agent, and it relays the dashboard's registry requests to the
 * tool server without being able to forge them (they carry the owner's passkey signature).
 *
 *   browser ──HTTP──▶ host ──IPC: MCP + RPC──▶ tool server (verifier, passkey registry)
 *                      ▲
 *                      └──IPC: MCP── agent (sandboxed)
 */
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import {
  fieldToHex,
  getHasher,
  LocalWasmProver,
  parseField,
  parseUint,
  PolicyOpening,
  ProofVerifier,
  type Prover,
  type RefusalLimit,
  recipientId,
} from '@zk-intent-firewall/mcp-firewall';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import type {
  ApprovalRequest,
  ApprovalResult,
  ChallengeRequest,
  ChallengeResponse,
  EnrollmentResult,
  FirewallLogEntry,
  HostEvent,
  LogResponse,
  PolicyOpeningWire,
  PreparePolicyRequest,
  PreparePolicyResponse,
  RunRequest,
  StateResponse,
  VerifierLogEntry,
  AgentStep,
  CommitmentStatus,
} from '../../shared/api.ts';
import { APPROVAL_LABEL } from '../../shared/approval.ts';
import { canonicalAccount, SCOPES, type ScopeName, TREASURY_SERVER_ID, USDC_ASSET_ID } from '../../shared/demo-config.ts';
import { isIpcMessage } from '../../ipc/channel.ts';
import { USER_INSTRUCTION } from '../../demo/inbox.ts';
import type { RegistryRecordView } from '../verifier/passkey-registry.ts';
import { FirewallHost } from './firewall-host.ts';
import { AGENT_ENTRY, spawnSandboxed } from './sandbox.ts';
import { ToolServerProcess, type WireTap } from './tool-server-process.ts';

export class HostError extends Error {
  override readonly name = 'HostError';
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export interface HostOptions {
  /** The dashboard's origin, for example http://localhost:5173. The RP ID is its hostname. */
  readonly origin: string;
  /** Default: 32 random bytes, hex. */
  readonly sessionToken?: string;
  readonly wireTap?: WireTap;
  /** Default true. */
  readonly precheck?: boolean;
  readonly refusalLimit?: RefusalLimit | false;
  /** The agent entry to run in the sandbox. Default src/agent/main.ts. */
  readonly agentEntry?: string;
  readonly proverThreads?: number;
  readonly inheritOutput?: boolean;
}

export interface RunResult {
  readonly runId: string;
  readonly exitCode: number | null;
  readonly steps: readonly AgentStep[];
  readonly firewall: readonly FirewallLogEntry[];
  readonly verifier: readonly VerifierLogEntry[];
  readonly agentOutput: string;
}

const MAX_LOG = 500;

export class Host {
  readonly origin: string;
  readonly rpId: string;
  readonly sessionToken: string;
  readonly toolServer: ToolServerProcess;
  readonly firewall: FirewallHost;
  readonly #o: HostOptions;
  readonly #prover: Prover;
  readonly #selfVerifier: ProofVerifier;
  readonly #listeners = new Set<(e: HostEvent) => void>();
  readonly #firewallLog: FirewallLogEntry[] = [];
  readonly #verifierLog: VerifierLogEntry[] = [];
  #currentRun: string | undefined;
  #running = false;

  private constructor(o: HostOptions, toolServer: ToolServerProcess, prover: Prover, selfVerifier: ProofVerifier, eventSink: { emit?: (e: HostEvent) => void }) {
    this.#o = o;
    this.origin = o.origin;
    this.rpId = new URL(o.origin).hostname;
    this.sessionToken = o.sessionToken ?? Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString('hex');
    this.toolServer = toolServer;
    this.#prover = prover;
    this.#selfVerifier = selfVerifier;
    eventSink.emit = (e) => this.#emit(e);
    this.firewall = new FirewallHost({
      prover,
      selfVerifier,
      upstream: toolServer.client,
      registry: toolServer.remoteRegistry(),
      serverId: TREASURY_SERVER_ID,
      ...(o.precheck !== undefined ? { precheck: o.precheck } : {}),
      ...(o.refusalLimit !== undefined ? { refusalLimit: o.refusalLimit } : {}),
      ...(o.wireTap ? { wireTap: (dir: 'in' | 'out', m: JSONRPCMessage) => o.wireTap!('agent', dir, m) } : {}),
      onDecision: (entry) => this.#emit({ type: 'firewall', ...(this.#currentRun ? { runId: this.#currentRun } : {}), entry }),
    });
  }

  static async start(o: HostOptions): Promise<Host> {
    const url = new URL(o.origin);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('origin must be http or https');
    // Events can arrive from the tool server before the Host object exists; route them late.
    const sink: { emit?: (e: HostEvent) => void } = {};
    const [toolServer, prover, selfVerifier] = await Promise.all([
      ToolServerProcess.start(
        { rpId: url.hostname, rpName: 'zk-intent-firewall demo', expectedOrigins: [url.origin], serverId: TREASURY_SERVER_ID },
        {
          onEvent: (entry) => sink.emit?.({ type: 'verifier', entry }),
          ...(o.wireTap ? { wireTap: o.wireTap } : {}),
          ...(o.inheritOutput ? { inheritOutput: true } : {}),
        },
      ),
      LocalWasmProver.create(o.proverThreads !== undefined ? { threads: o.proverThreads } : {}),
      ProofVerifier.create(),
    ]);
    return new Host(o, toolServer, prover, selfVerifier, sink);
  }

  // -- Events and log -----------------------------------------------------------------------------

  subscribe(listener: (e: HostEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #emit(e: HostEvent): void {
    if (e.type === 'firewall') push(this.#firewallLog, e.entry);
    if (e.type === 'verifier') {
      const tagged = this.#currentRun && e.runId === undefined ? { ...e, runId: this.#currentRun } : e;
      push(this.#verifierLog, tagged.entry);
      e = tagged;
    }
    for (const l of this.#listeners) {
      try {
        l(e);
      } catch {
        // A listener never breaks the host.
      }
    }
  }

  async log(): Promise<LogResponse> {
    const ledger = await this.toolServer.rpc.call<{ recipient: string; amount: string; at: string }[]>('ledger');
    return { firewall: [...this.#firewallLog], verifier: [...this.#verifierLog], ledger: ledger.map(({ recipient, amount, at }) => ({ recipient, amount, at })) };
  }

  checkToken(presented: unknown): boolean {
    if (typeof presented !== 'string') return false;
    const a = Buffer.from(presented);
    const b = Buffer.from(this.sessionToken);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  // -- State --------------------------------------------------------------------------------------

  async state(): Promise<StateResponse> {
    const info = await this.toolServer.rpc.call<{ rpId: string; ownerCredentialId: string | null; vkHashes: Record<string, string> }>('verifier.info');
    const armed = this.firewall.armedCommitment;
    return {
      passkey: info.ownerCredentialId ? { enrolled: true, credentialId: info.ownerCredentialId } : { enrolled: false },
      firewall: armed ? { armed: true, policyCommitment: armed } : { armed: false },
      verifier: { serverId: TREASURY_SERVER_ID, rpId: info.rpId, approvalLabel: APPROVAL_LABEL, vkHashes: info.vkHashes },
      demo: { running: this.#running },
    };
  }

  // -- Policy authoring ---------------------------------------------------------------------------

  /**
   * Computes a policy's commitment from its definition. Nothing is kept: the opening goes back to
   * the dashboard, which stores it, and comes back here only to arm the firewall.
   */
  async preparePolicy(req: PreparePolicyRequest): Promise<PreparePolicyResponse> {
    if (typeof req !== 'object' || req === null) throw new HostError(400, 'invalid request');
    if (!Array.isArray(req.recipients) || req.recipients.length === 0 || req.recipients.length > 1000) throw new HostError(400, 'between 1 and 1000 recipients');
    if (!Array.isArray(req.scopes) || req.scopes.length === 0) throw new HostError(400, 'at least one scope');
    let opening: PolicyOpening;
    try {
      const scopes = req.scopes.map((s) => {
        if (!Object.hasOwn(SCOPES, s)) throw new Error(`unknown scope ${String(s)}`);
        return SCOPES[s as ScopeName];
      });
      const maxAmount = parseUint(req.maxAmount, 128, 'maxAmount');
      if (maxAmount === 0n) throw new Error('maxAmount must be positive');
      const salt = parseField(req.salt, 'salt');
      if (salt < 1n << 128n) throw new Error('salt must carry at least 128 bits');
      opening = PolicyOpening.create(await getHasher(), {
        maxAmount,
        recipients: req.recipients.map((r) => recipientId(USDC_ASSET_ID, canonicalAccount(r))),
        scopes,
        expiry: parseUint(req.expiry, 64, 'expiry'),
        salt,
        allowlistOrder: 'sorted',
      });
    } catch (e) {
      throw new HostError(400, e instanceof Error ? e.message : 'invalid policy');
    }
    return { opening: opening.toJSON() as PolicyOpeningWire, policyCommitment: fieldToHex(opening.commitment) };
  }

  // -- Passkey and registry, relayed to the verifier ----------------------------------------------

  passkeyOptions(): Promise<unknown> {
    return this.#relay('enroll.options', {});
  }

  passkeyComplete(response: unknown): Promise<EnrollmentResult> {
    return this.#relay('enroll.complete', { response });
  }

  approvalChallenge(req: ChallengeRequest): Promise<ChallengeResponse> {
    return this.#relay('approval.issue', { action: req?.action, policyCommitment: req?.policyCommitment });
  }

  async registerPolicy(req: ApprovalRequest): Promise<ApprovalResult> {
    const r = await this.#relay<ApprovalResult>('policy.register', approvalParams(req));
    if (r.ok) this.#emit({ type: 'registry', policyCommitment: normaliseCommitment(req.policyCommitment), status: r.status });
    return r;
  }

  async revokePolicy(req: ApprovalRequest): Promise<ApprovalResult> {
    const r = await this.#relay<ApprovalResult>('policy.revoke', approvalParams(req));
    if (r.ok) this.#emit({ type: 'registry', policyCommitment: normaliseCommitment(req.policyCommitment), status: r.status });
    return r;
  }

  policyRecords(commitments: unknown): Promise<RegistryRecordView[]> {
    return this.#relay('policy.records', { commitments });
  }

  policyStatus(commitment: string): Promise<CommitmentStatus> {
    return this.#relay('policy.status', { policyCommitment: commitment });
  }

  async #relay<T>(method: string, params: unknown): Promise<T> {
    try {
      return await this.toolServer.rpc.call<T>(method, params);
    } catch (e) {
      throw new HostError(400, e instanceof Error ? e.message : 'request refused');
    }
  }

  // -- Firewall -----------------------------------------------------------------------------------

  async arm(opening: unknown): Promise<string> {
    if (this.#running) throw new HostError(409, 'a demo run is in progress');
    let commitment: string;
    try {
      commitment = await this.firewall.arm(opening as PolicyOpeningWire);
    } catch (e) {
      throw new HostError(400, e instanceof Error ? e.message : 'invalid policy opening');
    }
    this.#emit({ type: 'firewall_armed', policyCommitment: commitment });
    return commitment;
  }

  disarm(): void {
    if (this.#running) throw new HostError(409, 'a demo run is in progress');
    this.firewall.disarm();
    this.#emit({ type: 'firewall_disarmed' });
  }

  // -- Demo ---------------------------------------------------------------------------------------

  /** Runs the scripted agent once, in its sandbox, behind the firewall. One run at a time. */
  async runDemo(req: RunRequest = {}): Promise<RunResult> {
    if (!this.firewall.armedCommitment) throw new HostError(409, 'arm the firewall with a policy first');
    if (this.#running) throw new HostError(409, 'a demo run is already in progress');
    const options: Required<RunRequest> = {
      paceMs: Math.min(Math.max(Math.trunc(Number(req.paceMs ?? 0)) || 0, 0), 5000),
      firewallChecksRegistry: req.firewallChecksRegistry !== false,
    };
    this.#running = true;
    const runId = randomUUID();
    this.#currentRun = runId;
    const steps: AgentStep[] = [];
    const firewall: FirewallLogEntry[] = [];
    const verifier: VerifierLogEntry[] = [];
    const unsubscribe = this.subscribe((e) => {
      if (e.type === 'firewall' && e.runId === runId) firewall.push(e.entry);
      if (e.type === 'verifier' && e.runId === runId) verifier.push(e.entry);
    });
    this.#emit({ type: 'run_started', runId, options });

    const agent = spawnSandboxed(this.#o.agentEntry ?? AGENT_ENTRY, [`--pace=${options.paceMs}`, `--instruction=${USER_INSTRUCTION}`]);
    const { child } = agent;
    let session: { close: () => Promise<void> } | undefined;
    let error: string | undefined;
    const exited = new Promise<number | null>((r) => child.once('exit', (code) => r(code)));
    try {
      await new Promise<void>((resolveReady, rejectReady) => {
        child.on('message', (m) => {
          if (!isIpcMessage(m) || m.kind !== 'event') return;
          const ev = m.event as { type?: string; step?: AgentStep };
          if (ev.type === 'ready') resolveReady();
          else if (ev.type === 'agent' && ev.step) {
            steps.push(ev.step);
            this.#emit({ type: 'agent', runId, step: ev.step });
          }
        });
        void exited.then((code) => rejectReady(new Error(`agent exited with ${code} before it was ready:\n${agent.output()}`)));
      });
      session = await this.firewall.serve(child, { checkRegistry: options.firewallChecksRegistry });
      child.send({ kind: 'event', event: { type: 'start' } });
      const timer = setTimeout(() => child.kill('SIGKILL'), 180_000);
      await exited;
      clearTimeout(timer);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      if (child.exitCode === null) child.kill('SIGKILL');
    } finally {
      await session?.close();
      unsubscribe();
      this.#running = false;
      this.#currentRun = undefined;
    }
    const exitCode = child.exitCode;
    this.#emit({ type: 'run_finished', runId, exitCode, ...(error !== undefined ? { error } : {}) });
    return { runId, exitCode, steps, firewall, verifier, agentOutput: agent.output() };
  }

  async stop(): Promise<void> {
    await this.toolServer.stop();
    await Promise.allSettled([this.#prover.destroy(), this.#selfVerifier.destroy()]);
  }
}

function push<T>(list: T[], item: T): void {
  list.push(item);
  if (list.length > MAX_LOG) list.splice(0, list.length - MAX_LOG);
}

function approvalParams(req: ApprovalRequest): ApprovalRequest {
  return { policyCommitment: req?.policyCommitment, nonce: req?.nonce, response: req?.response } as ApprovalRequest;
}

function normaliseCommitment(c: unknown): string {
  try {
    return fieldToHex(parseField(c));
  } catch {
    return String(c);
  }
}
