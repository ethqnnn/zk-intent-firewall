/**
 * The break-it engine: every party of the real system, wired as in production, around a fake
 * ledger. Nothing on the security path is re-implemented here; it is all imported:
 *
 *   firewall (prover side)      IntentFirewall, createFirewallProxy, LocalWasmProver   packages/mcp-firewall
 *   tool server (verifier side) IntentVerifier, requireProofOfIntent, ProofVerifier    packages/mcp-firewall
 *   policy and circuit          PolicyOpening, the compiled proof_of_intent circuit    packages/mcp-firewall, packages/zk-circuit
 *   passkey approval            PasskeyPolicyRegistry                                 apps/demo-dashboard
 *   tool definitions            sendPayment, canonicalAccount                         apps/demo-dashboard
 *
 * The owner. At boot the engine creates a software passkey (SoftAuthenticator, a real P-256 key),
 * enrols it as the policy owner, approves the published policy with it, and then drops it. After
 * boot no owner key exists anywhere: no request can make the owner sign anything, and every
 * accepted enrolment or approval afterwards is by definition not the owner's, hence a break.
 *
 * The opening (with its secret salt) lives only in this process, inside the firewall sessions. No
 * response carries it.
 *
 * This process runs without network access (see front/engine-process.ts): it talks to the front
 * process over IPC only.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import {
  createFirewallProxy,
  DEFAULT_FRESHNESS,
  DEFAULT_REFUSAL_LIMIT,
  encodeEnvelope,
  type FirewallDecision,
  fieldToHex,
  getHasher,
  INTENT_META_KEY,
  IntentFirewall,
  IntentVerifier,
  LocalWasmProver,
  PolicyOpening,
  ProofVerifier,
  type Prover,
  unixNow,
} from '@zk-intent-firewall/mcp-firewall';
import { PasskeyPolicyRegistry } from '@zk-intent-firewall/demo-dashboard/src/server/verifier/passkey-registry.ts';
import { SoftAuthenticator } from '@zk-intent-firewall/demo-dashboard/src/demo/soft-authenticator.ts';
import { FAKE_UNIT } from '../shared/notice.ts';
import type { AttemptDraft, CaughtBy, EngineAnswer, StatusView } from '../shared/types.ts';
import {
  ASSET_ID,
  BREAK_IT_POLICY,
  type BreakItPolicy,
  breakItCatalog,
  DECIMALS,
  NOT_ALLOWLISTED,
  OPENING_BALANCE,
  PASSTHROUGH_TOOLS,
  PROTECTED_TOOLS,
  SCOPES,
  TOOL_DESCRIPTIONS,
} from './deployment.ts';
import { FakeLedger } from './ledger.ts';
import { PolicyOracle, type PublishedPolicy } from './oracle.ts';
import { argumentsSummary, clip, envelopeSummary, jsonSize, metaKeys } from './summary.ts';
import { CALL_ID_META, createToolServer, type ToolServerEvent } from './tool-server.ts';

export interface EngineOptions {
  /** The public origin of the page, for example `https://break-it.example.com`. */
  readonly origin: string;
  /** Barretenberg's reference-string directory. It must already be populated (no network). */
  readonly crsPath?: string;
  /** WASM threads for the prover. Default 2. */
  readonly proverThreads?: number;
  /** Firewall sessions kept (one per client, per precheck setting). Default 500. */
  readonly maxSessions?: number;
  /** Default true: top the treasury back up when it falls below the per-payment limit. */
  readonly autoTopUp?: boolean;
  readonly policy?: BreakItPolicy;
  readonly openingBalance?: bigint;
  readonly clock?: () => bigint;
  /** Tests only: a prover to use instead of LocalWasmProver. */
  readonly prover?: Prover;
  /**
   * Tests only: what the break detector believes was published, when it should differ from the
   * policy actually in force. A test uses it to check that an accepted out-of-policy payment is
   * reported as a break.
   */
  readonly publishedPolicyOverride?: Partial<PublishedPolicy>;
}

/** Collects the firewall decisions made while handling one attempt. */
const attemptScope = new AsyncLocalStorage<{ decisions: FirewallDecision[] }>();

interface FirewallLink {
  readonly firewall: IntentFirewall;
  /** An MCP client connected to the firewall proxy: the agent's seat. */
  readonly agent: Client;
  readonly close: () => Promise<void>;
}

const MAX_ARGS_JSON = 4096;
const MAX_META_JSON = 64 * 1024;

class EngineRequestError extends Error {}

export class BreakItEngine {
  readonly startedAt = new Date().toISOString();
  readonly #o: EngineOptions;
  readonly #clock: () => bigint;
  readonly #policy: PolicyOpening;
  readonly #registry: PasskeyPolicyRegistry;
  readonly #verifier: IntentVerifier;
  readonly #ledger: FakeLedger;
  readonly #oracle: PolicyOracle;
  readonly #prover: Prover;
  readonly #ownsProver: boolean;
  readonly #selfVerifier: ProofVerifier;
  readonly #direct: Client;
  readonly #toolEvents = new Map<string, ToolServerEvent>();
  readonly #sessions = new Map<string, Promise<FirewallLink>>();

  private constructor(
    o: EngineOptions,
    parts: {
      policy: PolicyOpening;
      registry: PasskeyPolicyRegistry;
      verifier: IntentVerifier;
      ledger: FakeLedger;
      oracle: PolicyOracle;
      prover: Prover;
      selfVerifier: ProofVerifier;
      direct: Client;
    },
  ) {
    this.#o = o;
    this.#clock = o.clock ?? unixNow;
    this.#policy = parts.policy;
    this.#registry = parts.registry;
    this.#verifier = parts.verifier;
    this.#ledger = parts.ledger;
    this.#oracle = parts.oracle;
    this.#prover = parts.prover;
    this.#ownsProver = o.prover === undefined;
    this.#selfVerifier = parts.selfVerifier;
    this.#direct = parts.direct;
  }

  static async create(o: EngineOptions): Promise<BreakItEngine> {
    const clock = o.clock ?? unixNow;
    const origin = new URL(o.origin).origin;
    const rpId = new URL(origin).hostname;
    const def = o.policy ?? BREAK_IT_POLICY;
    const crs = o.crsPath !== undefined ? { crsPath: o.crsPath } : {};

    // The verifier party's registry, gated by the owner's passkey.
    const registry = new PasskeyPolicyRegistry({ rpId, rpName: 'zk-intent-firewall break-it (fake money)', expectedOrigins: [origin], clock });

    // The policy in force. Its salt is drawn here, from the CSPRNG, and never leaves this process.
    const hasher = await getHasher();
    const policy = PolicyOpening.create(hasher, {
      maxAmount: def.maxAmount,
      recipients: def.payees.map((p) => ({ assetId: ASSET_ID, accountId: p.account })),
      scopes: def.scopes.map((s) => SCOPES[s]),
      expiry: clock() + def.validForSeconds,
    });
    await approveAtBoot(registry, origin, rpId, fieldToHex(policy.commitment));

    const serverId = `${origin}/mcp`;
    const [verifier, selfVerifier, prover] = await Promise.all([
      IntentVerifier.create({ catalog: breakItCatalog(serverId), registry, proofVerifier: await ProofVerifier.create(crs), clock }),
      ProofVerifier.create(crs),
      o.prover ?? LocalWasmProver.create({ threads: o.proverThreads ?? 2, ...crs }),
    ]);

    const ledger = new FakeLedger({ openingBalance: o.openingBalance ?? OPENING_BALANCE, topUpBelow: o.autoTopUp === false ? 0n : def.maxAmount, clock });
    const grantedTools = PROTECTED_TOOLS.filter((t) => def.scopes.includes(t.scope as never)).map((t) => t.name);
    const oracle = new PolicyOracle({
      policyCommitment: fieldToHex(policy.commitment),
      maxAmount: def.maxAmount,
      allowlist: def.payees.map((p) => p.account),
      grantedTools,
      expiry: policy.fields.expiry,
      ...o.publishedPolicyOverride,
    });

    const direct = new Client({ name: 'break-it-direct-caller', version: '0.1.0' });
    const engine = new BreakItEngine(o, { policy, registry, verifier, ledger, oracle, prover, selfVerifier, direct });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await engine.#newToolServer().connect(a);
    await direct.connect(b);
    return engine;
  }

  #newToolServer() {
    return createToolServer({
      verifier: this.#verifier,
      ledger: this.#ledger,
      oracle: this.#oracle,
      onEvent: (e) => {
        if (e.callId === '') return;
        this.#toolEvents.set(e.callId, e);
        // Bounded: entries are taken by the attempt that made them; this only drops strays.
        if (this.#toolEvents.size > 1000) this.#toolEvents.delete(this.#toolEvents.keys().next().value!);
      },
    });
  }

  #takeToolEvent(callId: string): ToolServerEvent | undefined {
    const e = this.#toolEvents.get(callId);
    this.#toolEvents.delete(callId);
    return e;
  }

  get policyCommitment(): string {
    return fieldToHex(this.#policy.commitment);
  }

  get ledger(): FakeLedger {
    return this.#ledger;
  }

  // -- Status --------------------------------------------------------------------------------

  status(): StatusView {
    const def = this.#o.policy ?? BREAK_IT_POLICY;
    const origin = new URL(this.#o.origin).origin;
    const limit = DEFAULT_REFUSAL_LIMIT;
    const granted = new Set<string>(def.scopes);
    return {
      startedAt: this.startedAt,
      policy: {
        policyCommitment: this.policyCommitment,
        maxAmount: def.maxAmount.toString(),
        allowlist: def.payees.map((p) => ({ label: p.label, account: p.account })),
        grantedScopes: [...def.scopes],
        expiry: this.#policy.fields.expiry.toString(),
        expiresAt: new Date(Number(this.#policy.fields.expiry) * 1000).toISOString(),
        salt: 'secret',
      },
      asset: { id: ASSET_ID, decimals: DECIMALS, unit: FAKE_UNIT },
      tools: [
        ...PROTECTED_TOOLS.map((t) => ({ name: t.name, protected: true, scope: String(t.scope), granted: granted.has(String(t.scope)), description: TOOL_DESCRIPTIONS[t.name] ?? '' })),
        ...PASSTHROUGH_TOOLS.map((name) => ({ name, protected: false, description: TOOL_DESCRIPTIONS[name] ?? '' })),
      ],
      notAllowlisted: [NOT_ALLOWLISTED.lookalike, NOT_ALLOWLISTED.litware],
      verifier: {
        serverId: this.#verifier.catalog.serverId,
        rpId: this.#registry.rpId,
        origin,
        ownerCredentialId: this.#registry.ownerCredentialId ?? null,
        vkHashes: this.#registry.vkHashes(),
        freshness: { maxAgeSeconds: Number(DEFAULT_FRESHNESS.maxAgeSeconds), maxFutureSkewSeconds: Number(DEFAULT_FRESHNESS.maxFutureSkewSeconds) },
        registry: { status: this.#registry.status(this.#policy.commitment) },
      },
      firewall: { refusalLimit: { maxRefusals: limit.maxRefusals, windowSeconds: Number(limit.windowSeconds), lockoutSeconds: Number(limit.lockoutSeconds) } },
      ledger: this.#ledger.snapshot(),
    };
  }

  // -- Firewall sessions -------------------------------------------------------------------------

  /**
   * One firewall per client and precheck setting, so that one visitor tripping the firewall's
   * refusal lockout (5 refusals in 60 s) locks out only themselves. All share one prover and one
   * self-verifier; the prover makes one proof at a time.
   */
  #session(client: string, precheck: boolean): Promise<FirewallLink> {
    const key = `${client}|${precheck ? 'precheck' : 'circuit-only'}`;
    const existing = this.#sessions.get(key);
    if (existing) {
      // Most recently used last.
      this.#sessions.delete(key);
      this.#sessions.set(key, existing);
      return existing;
    }
    const created = this.#newSession(precheck);
    this.#sessions.set(key, created);
    created.catch(() => this.#sessions.delete(key));
    const max = this.#o.maxSessions ?? 500;
    while (this.#sessions.size > max) {
      const [oldKey, old] = this.#sessions.entries().next().value!;
      this.#sessions.delete(oldKey);
      void old.then((l) => l.close()).catch(() => undefined);
    }
    return created;
  }

  async #newSession(precheck: boolean): Promise<FirewallLink> {
    const firewall = await IntentFirewall.create({
      policy: this.#policy,
      catalog: breakItCatalog(this.#verifier.catalog.serverId),
      prover: this.#prover,
      selfVerifier: this.#selfVerifier,
      passthroughTools: [...PASSTHROUGH_TOOLS],
      precheck,
      registry: this.#registry,
      clock: this.#clock,
      onDecision: (d) => attemptScope.getStore()?.decisions.push(d),
    });
    const [toolSide, upstreamSide] = InMemoryTransport.createLinkedPair();
    const toolServer = this.#newToolServer();
    await toolServer.connect(toolSide);
    const upstream = new Client({ name: 'break-it-firewall-upstream', version: '0.1.0' });
    await upstream.connect(upstreamSide);
    const proxy = createFirewallProxy({ firewall, upstream });
    const [proxySide, agentSide] = InMemoryTransport.createLinkedPair();
    await proxy.connect(proxySide);
    const agent = new Client({ name: 'break-it-visitor-agent', version: '0.1.0' });
    await agent.connect(agentSide);
    return {
      firewall,
      agent,
      close: async () => {
        await agent.close().catch(() => undefined);
        await upstream.close().catch(() => undefined);
        await firewall.destroy().catch(() => undefined);
      },
    };
  }

  // -- Attempts ------------------------------------------------------------------------------------

  /**
   * "You are the agent": the call goes to the firewall, as an agent's would, for example one an
   * injected prompt steered. `mode: "forward"` (default) sends it through the real firewall proxy to
   * the tool server; `mode: "prove-only"` asks the firewall for the proof and hands it back unspent,
   * to be reused, moved or tampered with on the direct route.
   */
  async attemptAgent(client: string, body: unknown): Promise<EngineAnswer> {
    const started = performance.now();
    let req;
    try {
      req = parseToolCall(body);
    } catch (e) {
      return invalid('agent', e, started);
    }
    const mode = (body as Record<string, unknown>)['mode'] === 'prove-only' ? 'prove-only' : 'forward';
    const precheck = (body as Record<string, unknown>)['precheck'] !== false;
    const attempted = { tool: req.tool, arguments: argumentsSummary(req.args), mode, precheck } as const;
    const link = await this.#session(client, precheck);
    const scope = { decisions: [] as FirewallDecision[] };

    if (mode === 'prove-only') {
      const auth = await attemptScope.run(scope, () => link.firewall.authorize(req.tool, req.args));
      const decision = scope.decisions.at(-1);
      const operator = operatorView(decision);
      if (!auth.allowed) {
        return answer(200, { agentSees: `Blocked by the intent firewall: this action is not authorised. Decision ${auth.decisionId}.`, operatorLog: operator }, {
          route: 'agent', attempted, result: 'blocked', caughtBy: firewallCheck(decision), verdict: 'caught', ms: ms(started),
        });
      }
      if (!auth.protected) {
        return answer(200, { note: `${req.tool} is read-only and passes through without a proof; nothing to hand back.`, operatorLog: operator }, {
          route: 'agent', attempted, result: 'served', caughtBy: null, verdict: 'legitimate', ms: ms(started),
        });
      }
      const envelope = encodeEnvelope(auth.envelope);
      const breakReasons = this.#oracle.violations({ tool: req.tool, arguments: req.args, policyCommitment: envelope.policy_commitment, at: auth.envelope.currentTimestamp }).map((r) => `firewall_proved_${r}`);
      return answer(
        200,
        {
          operatorLog: operator,
          envelope,
          meta: { [INTENT_META_KEY]: envelope },
          hint: `Unspent proof for ${req.tool}. It is valid for ${DEFAULT_FRESHNESS.maxAgeSeconds}s. Send it to POST /api/attempt/direct as "meta", with the same or different arguments.`,
        },
        {
          route: 'agent', attempted, result: 'proof_issued', caughtBy: null, verdict: breakReasons.length > 0 ? 'break' : 'legitimate',
          ...(breakReasons.length > 0 ? { breakReasons } : {}), ms: ms(started),
        },
      );
    }

    const callId = randomUUID();
    const result = (await attemptScope.run(scope, () => link.agent.callTool({ name: req.tool, arguments: req.args, _meta: { [CALL_ID_META]: callId } }))) as CallToolResult;
    const decision = scope.decisions.at(-1);
    const event = this.#takeToolEvent(callId);
    const agentSees = resultText(result);
    const operator = operatorView(decision);

    if (decision === undefined) {
      return answer(200, { agentSees }, { route: 'agent', attempted, result: 'rejected', caughtBy: { layer: 'request', check: 'not_a_tool_call' }, verdict: 'caught', ms: ms(started) });
    }
    if (!decision.allowed) {
      return answer(200, { agentSees, operatorLog: operator }, { route: 'agent', attempted, result: 'blocked', caughtBy: firewallCheck(decision), verdict: 'caught', ms: ms(started) });
    }
    // The firewall let it through. Did it prove something the policy does not allow?
    const firewallBreaks =
      decision.action !== undefined
        ? this.#oracle.violations({ tool: req.tool, arguments: req.args, policyCommitment: this.policyCommitment, at: decision.at }).map((r) => `firewall_proved_${r}`)
        : [];
    const out = this.#toolOutcome('agent', attempted, event, result, started, firewallBreaks);
    return { ...out, response: { agentSees, operatorLog: operator, ...out.response } };
  }

  /**
   * "You are calling the tool server directly", around the firewall, with whatever `_meta` you
   * like: no proof, a garbled one, a replayed one, one made for another call.
   */
  async attemptDirect(_client: string, body: unknown): Promise<EngineAnswer> {
    const started = performance.now();
    let req;
    try {
      req = parseToolCall(body);
    } catch (e) {
      return invalid('direct', e, started);
    }
    const rawMeta = (body as Record<string, unknown>)['meta'];
    if (rawMeta !== undefined && (typeof rawMeta !== 'object' || rawMeta === null || Array.isArray(rawMeta))) return invalid('direct', new EngineRequestError('meta must be an object'), started);
    if (jsonSize(rawMeta) > MAX_META_JSON) return invalid('direct', new EngineRequestError('meta is too large'), started);
    const meta = { ...((rawMeta as Record<string, unknown> | undefined) ?? {}) };
    const attempted = { tool: req.tool, arguments: argumentsSummary(req.args), envelope: envelopeSummary(meta), metaKeys: metaKeys(meta) };
    const callId = randomUUID();
    // The call id is this engine's own correlation label; a caller cannot set it.
    meta[CALL_ID_META] = callId;
    let result: CallToolResult;
    try {
      result = (await this.#direct.callTool({ name: req.tool, arguments: req.args, _meta: meta })) as CallToolResult;
    } catch (e) {
      return answer(200, { error: clip(e instanceof Error ? e.message : String(e), 300) }, { route: 'direct', attempted, result: 'rejected', caughtBy: { layer: 'mcp-schema', check: 'mcp_error' }, verdict: 'caught', ms: ms(started) });
    }
    return this.#toolOutcome('direct', attempted, this.#takeToolEvent(callId), result, started, []);
  }

  #toolOutcome(route: 'agent' | 'direct', attempted: AttemptDraft['attempted'], event: ToolServerEvent | undefined, result: CallToolResult, started: number, extraBreaks: readonly string[]): EngineAnswer {
    const toolServerSees = resultText(result);
    const base = { route, attempted, ms: ms(started) };
    if (event === undefined) {
      // No handler ran: the MCP layer refused the call (unknown tool, or arguments that do not fit
      // the input schema).
      const check = /not found/i.test(toolServerSees) ? 'unknown_tool' : /validation/i.test(toolServerSees) ? 'input_schema' : 'mcp_error';
      return answer(200, { toolServer: toolServerSees }, { ...base, result: 'rejected', caughtBy: { layer: 'mcp-schema', check }, verdict: extraBreaks.length > 0 ? 'break' : 'caught', ...(extraBreaks.length > 0 ? { breakReasons: extraBreaks } : {}) });
    }
    if (event.outcome === 'served') {
      return answer(200, { toolServer: toolServerSees }, { ...base, result: 'served', caughtBy: null, verdict: 'legitimate' });
    }
    if (event.outcome === 'rejected') {
      return answer(200, { toolServer: toolServerSees, verifier: { reason: event.reason, ...(event.detail ? { detail: clip(event.detail, 300) } : {}) } }, {
        ...base, result: 'rejected', caughtBy: { layer: 'verifier', check: event.reason }, verdict: extraBreaks.length > 0 ? 'break' : 'caught', ...(extraBreaks.length > 0 ? { breakReasons: extraBreaks } : {}),
      });
    }
    const breakReasons = [...extraBreaks, ...event.breakReasons];
    const verdict = breakReasons.length > 0 ? 'break' : event.outcome === 'executed' ? 'legitimate' : 'caught';
    const response = {
      toolServer: toolServerSees,
      verifier: { accepted: true, publicInputs: event.publicInputs },
      ...(event.envelope ? { envelope: event.envelope, hint: 'This proof is spent. Try it again, or with other arguments, on POST /api/attempt/direct.' } : {}),
      ledger: { balance: this.#ledger.balance.toString() },
      ...(breakReasons.length > 0 ? { BREAK: 'The verifier accepted an action the published policy does not allow. Please report it privately.', breakReasons } : {}),
    };
    if (event.outcome === 'insufficient_funds') {
      return answer(200, response, { ...base, result: 'rejected', caughtBy: { layer: 'ledger', check: 'insufficient_funds' }, verdict, ...(breakReasons.length > 0 ? { breakReasons } : {}) });
    }
    return answer(200, response, { ...base, result: 'executed', caughtBy: null, verdict, ...(breakReasons.length > 0 ? { breakReasons } : {}), ...(event.payment ? { payment: event.payment } : {}) });
  }

  /** Issues an approval challenge, exactly as the dashboard relays one. Not an attempt by itself. */
  async passkeyChallenge(query: unknown): Promise<EngineAnswer> {
    const q = (query ?? {}) as Record<string, unknown>;
    try {
      return { http: 200, response: { challenge: await this.#registry.issueApproval(q['action'], q['policyCommitment']) } };
    } catch (e) {
      return { http: 400, response: { error: clip(e instanceof Error ? e.message : String(e), 300) } };
    }
  }

  /**
   * A register or revoke approval, checked by PasskeyPolicyRegistry as on the real tool server.
   * The owner key no longer exists, so any acceptance is a break.
   */
  async attemptPasskey(_client: string, body: unknown): Promise<EngineAnswer> {
    const started = performance.now();
    const b = (typeof body === 'object' && body !== null ? body : {}) as Record<string, unknown>;
    const action = b['action'];
    const response = b['response'] as Record<string, unknown> | undefined;
    const attempted = {
      passkey: {
        action: typeof action === 'string' ? clip(action, 16) : '?',
        ...(typeof b['policyCommitment'] === 'string' ? { policyCommitment: clip(b['policyCommitment'], 80) } : {}),
        ...(typeof response?.['id'] === 'string' ? { credentialId: clip(response['id'], 64) } : {}),
      },
    };
    if (action !== 'register' && action !== 'revoke') return invalid('passkey', new EngineRequestError('action must be register or revoke'), started);
    if (jsonSize(body) > MAX_META_JSON) return invalid('passkey', new EngineRequestError('request is too large'), started);
    const req = { policyCommitment: b['policyCommitment'], nonce: b['nonce'], response: b['response'] } as Parameters<PasskeyPolicyRegistry['approveRegistration']>[0];
    const r = action === 'register' ? await this.#registry.approveRegistration(req) : await this.#registry.approveRevocation(req);
    if (r.ok) {
      return answer(200, { registry: r, BREAK: 'The registry accepted an approval the owner never signed. Please report it privately.' }, {
        route: 'passkey', attempted, result: 'approved', caughtBy: null, verdict: 'break', breakReasons: [`${action}_approved_without_the_owner_key`], ms: ms(started),
      });
    }
    return answer(200, { registry: { ok: false, reason: r.reason, ...(r.detail ? { detail: clip(r.detail, 300) } : {}) } }, {
      route: 'passkey', attempted, result: 'rejected', caughtBy: { layer: 'passkey-registry', check: r.reason }, verdict: 'caught', ms: ms(started),
    });
  }

  /** Enrolment of a second owner passkey. Enrolment closed at boot (trust on first use). */
  async attemptEnroll(_client: string, body: unknown): Promise<EngineAnswer> {
    const started = performance.now();
    const b = (typeof body === 'object' && body !== null ? body : {}) as Record<string, unknown>;
    const stage = b['stage'] === 'complete' ? 'complete' : 'options';
    const attempted = { passkey: { stage } };
    if (jsonSize(body) > MAX_META_JSON) return invalid('enroll', new EngineRequestError('request is too large'), started);
    if (stage === 'options') {
      try {
        const options = await this.#registry.enrollmentOptions();
        return answer(200, { options, BREAK: 'Enrolment reopened after the owner enrolled.' }, { route: 'enroll', attempted, result: 'approved', caughtBy: null, verdict: 'break', breakReasons: ['enrolment_reopened'], ms: ms(started) });
      } catch (e) {
        return answer(200, { registry: { ok: false, reason: 'owner_already_enrolled', detail: e instanceof Error ? e.message : String(e) } }, {
          route: 'enroll', attempted, result: 'rejected', caughtBy: { layer: 'passkey-registry', check: 'owner_already_enrolled' }, verdict: 'caught', ms: ms(started),
        });
      }
    }
    const r = await this.#registry.completeEnrollment(b['response']);
    if (r.ok) {
      return answer(200, { registry: r, BREAK: 'A second owner passkey was enrolled.' }, { route: 'enroll', attempted, result: 'approved', caughtBy: null, verdict: 'break', breakReasons: ['second_owner_enrolled'], ms: ms(started) });
    }
    return answer(200, { registry: { ok: false, reason: r.reason } }, { route: 'enroll', attempted, result: 'rejected', caughtBy: { layer: 'passkey-registry', check: r.reason }, verdict: 'caught', ms: ms(started) });
  }

  async destroy(): Promise<void> {
    for (const s of this.#sessions.values()) await s.then((l) => l.close()).catch(() => undefined);
    this.#sessions.clear();
    await this.#direct.close().catch(() => undefined);
    await this.#verifier.destroy().catch(() => undefined);
    await this.#selfVerifier.destroy().catch(() => undefined);
    if (this.#ownsProver) await this.#prover.destroy().catch(() => undefined);
  }
}

/**
 * Enrols a one-time software owner passkey, approves `commitmentHex` with it through the registry's
 * normal approval path, and lets the key go out of scope. Throws unless both steps succeed.
 */
async function approveAtBoot(registry: PasskeyPolicyRegistry, origin: string, rpId: string, commitmentHex: string): Promise<void> {
  // The only reference to the owner key; it is unreachable once this function returns.
  const owner = new SoftAuthenticator({ origin, rpId });
  const enrolled = await registry.completeEnrollment(owner.createRegistrationResponse(await registry.enrollmentOptions()));
  if (!enrolled.ok) throw new Error(`owner enrolment failed: ${enrolled.reason}`);
  const challenge = await registry.issueApproval('register', commitmentHex);
  const approved = await registry.approveRegistration({ policyCommitment: commitmentHex, nonce: challenge.statement.nonce, response: owner.createAssertion(challenge.challenge) });
  if (!approved.ok || approved.status !== 'active') throw new Error('the published policy could not be approved at boot');
}

function parseToolCall(body: unknown): { tool: string; args: Record<string, unknown> } {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new EngineRequestError('the body must be a JSON object');
  const b = body as Record<string, unknown>;
  if (typeof b['tool'] !== 'string' || b['tool'].length === 0 || b['tool'].length > 64) throw new EngineRequestError('tool must be a tool name (1 to 64 characters)');
  const args = b['arguments'] ?? {};
  if (typeof args !== 'object' || args === null || Array.isArray(args)) throw new EngineRequestError('arguments must be an object');
  if (jsonSize(args) > MAX_ARGS_JSON) throw new EngineRequestError(`arguments must be at most ${MAX_ARGS_JSON} bytes of JSON`);
  return { tool: b['tool'], args: args as Record<string, unknown> };
}

function firewallCheck(d: FirewallDecision | undefined): CaughtBy {
  if (d === undefined || d.reason === undefined) return { layer: 'firewall', check: 'unknown' };
  if (d.reason === 'circuit_rejected') return { layer: 'circuit', check: 'circuit_rejected', ...(d.assertion !== undefined ? { assertion: d.assertion } : {}) };
  return { layer: 'firewall', check: d.reason };
}

/**
 * The firewall decision as the operator's log shows it. In production the agent sees only the
 * opaque refusal (spec L10); here the policy is published anyway, so the reason is shown. The
 * decision's free-text `detail` is left out except for argument-mapping errors, which describe the
 * arguments only.
 */
function operatorView(d: FirewallDecision | undefined): Record<string, unknown> | undefined {
  if (d === undefined) return undefined;
  return {
    decisionId: d.decisionId,
    allowed: d.allowed,
    ...(d.reason !== undefined ? { reason: d.reason } : {}),
    ...(d.assertion !== undefined ? { assertion: d.assertion } : {}),
    ...(d.reason === 'malformed_arguments' && d.detail !== undefined ? { detail: clip(d.detail, 300) } : {}),
  };
}

function resultText(r: CallToolResult): string {
  const parts = (r.content ?? []).flatMap((c) => (c.type === 'text' ? [c.text] : []));
  return clip(parts.join('\n'), 1000);
}

function ms(started: number): number {
  return Math.round(performance.now() - started);
}

function answer(http: number, response: Record<string, unknown>, draft: AttemptDraft): EngineAnswer {
  return { http, response, draft };
}

function invalid(route: AttemptDraft['route'], e: unknown, started: number): EngineAnswer {
  const message = e instanceof EngineRequestError ? e.message : 'invalid request';
  return answer(400, { error: message }, { route, attempted: {}, result: 'invalid_request', caughtBy: { layer: 'request', check: 'invalid_request' }, verdict: 'caught', ms: ms(started) });
}
