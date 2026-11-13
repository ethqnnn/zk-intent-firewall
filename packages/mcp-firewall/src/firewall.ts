/**
 * The prover side: decides, before a tool call leaves the agent's side, whether it may go, and
 * attaches a proof of intent to every protected call that may.
 *
 * The policy opening lives here and nowhere the agent can reach. The agent only ever learns that a
 * call was allowed or blocked, plus an opaque decision ID; the reason goes to the operator through
 * `onDecision` (spec L10: refusals leak the policy to whoever sees them).
 */
import { randomUUID } from 'node:crypto';
import type { CircuitAssertion, VerifierTarget } from './circuit.js';
import { getHasher, type ProtocolHasher } from './crypto/hash.js';
import { randomNonce } from './crypto/identifiers.js';
import type { Action } from './crypto/types.js';
import type { IntentEnvelope } from './envelope.js';
import type { PolicyOpening, PolicyViolation } from './policy.js';
import { ProofGenerationError, type Prover } from './prover/types.js';
import { ProofVerifier } from './verifier/proof-verifier.js';
import { type PolicyRegistry, unixNow } from './verifier/registry.js';
import { ActionMappingError, type ToolArguments, type ToolCatalog } from './tools.js';

export type BlockReason =
  /** The tool is neither protected nor explicitly passed through. */
  | 'unlisted_tool'
  /** The arguments do not describe a well-formed action. */
  | 'malformed_arguments'
  /** The registry says the active policy is revoked or unknown. */
  | 'policy_not_active'
  /** The pre-check found the action outside the policy. */
  | PolicyViolation
  /** Witness generation failed: the circuit itself refused the action. */
  | 'circuit_rejected'
  /** The backend failed to produce a proof. */
  | 'proving_failed'
  /** The proof did not verify against the pinned key for the action's own public inputs. */
  | 'self_verification_failed'
  /** Too many recent refusals: protected calls are locked out for a while. */
  | 'rate_limited'
  /** An unexpected error. The firewall fails closed. */
  | 'internal_error';

export type Authorization =
  | { readonly allowed: true; readonly protected: false; readonly decisionId: string }
  | {
      readonly allowed: true;
      readonly protected: true;
      readonly decisionId: string;
      readonly action: Action;
      readonly envelope: IntentEnvelope;
    }
  | { readonly allowed: false; readonly decisionId: string; readonly reason: BlockReason };

/** What the operator sees. Never forward this to the agent. */
export interface FirewallDecision {
  readonly decisionId: string;
  readonly toolName: string;
  readonly allowed: boolean;
  readonly reason?: BlockReason;
  /** The circuit assertion that refused the action, when the circuit did. */
  readonly assertion?: CircuitAssertion;
  readonly detail?: string;
  readonly action?: Omit<Action, 'nonce'>;
  /** Unix seconds. */
  readonly at: bigint;
}

export interface RefusalLimit {
  /** Refusals tolerated inside the window. */
  readonly maxRefusals: number;
  readonly windowSeconds: bigint;
  /** How long protected calls stay blocked once the limit is hit. */
  readonly lockoutSeconds: bigint;
}

export const DEFAULT_REFUSAL_LIMIT: RefusalLimit = { maxRefusals: 5, windowSeconds: 60n, lockoutSeconds: 300n };

export interface IntentFirewallOptions {
  /** The opening of the active policy. Held by the firewall only. */
  readonly policy: PolicyOpening;
  /** The protected tools of the upstream server, with that server's identity. */
  readonly catalog: ToolCatalog;
  readonly prover: Prover;
  /** Checks each proof before it leaves. Default: a new ProofVerifier. */
  readonly selfVerifier?: ProofVerifier;
  /** Default `noir-recursive`. */
  readonly target?: VerifierTarget;
  /** Tools that need no proof (for example read-only ones). Every other unlisted tool is blocked. */
  readonly passthroughTools?: readonly string[];
  /**
   * Refuse early, without proving, when the policy pre-check fails. Default true. With false,
   * every protected call goes to the circuit, which is still the authority.
   */
  readonly precheck?: boolean;
  /** When given, the firewall refuses to prove under a commitment that is not active. */
  readonly registry?: PolicyRegistry;
  /** Default DEFAULT_REFUSAL_LIMIT. `false` disables it. */
  readonly refusalLimit?: RefusalLimit | false;
  readonly clock?: () => bigint;
  /** Default: 31 bytes from the CSPRNG per call. */
  readonly nonceSource?: () => bigint;
  readonly onDecision?: (decision: FirewallDecision) => void;
}

export class IntentFirewall {
  readonly #o: IntentFirewallOptions;
  readonly #hasher: ProtocolHasher;
  readonly #self: ProofVerifier;
  readonly #ownsSelf: boolean;
  readonly #passthrough: ReadonlySet<string>;
  readonly #clock: () => bigint;
  #refusals: bigint[] = [];
  #lockedUntil = -1n;

  private constructor(o: IntentFirewallOptions, hasher: ProtocolHasher, self: ProofVerifier, ownsSelf: boolean) {
    for (const name of o.passthroughTools ?? []) {
      if (o.catalog.has(name)) throw new Error(`tool ${name} is protected and cannot also pass through`);
    }
    this.#o = o;
    this.#hasher = hasher;
    this.#self = self;
    this.#ownsSelf = ownsSelf;
    this.#passthrough = new Set(o.passthroughTools ?? []);
    this.#clock = o.clock ?? unixNow;
  }

  static async create(options: IntentFirewallOptions): Promise<IntentFirewall> {
    const owns = options.selfVerifier === undefined;
    const [hasher, self] = await Promise.all([getHasher(), options.selfVerifier ?? ProofVerifier.create()]);
    return new IntentFirewall(options, hasher, self, owns);
  }

  /** The commitment of the active policy, which verifiers must have registered. */
  get policyCommitment(): bigint {
    return this.#o.policy.commitment;
  }

  /**
   * Decides on one tool call. Never throws for a call it refuses; an unexpected internal error is
   * also a refusal (fail closed).
   */
  async authorize(toolName: string, args: ToolArguments): Promise<Authorization> {
    const decisionId = randomUUID();
    try {
      return await this.#authorize(decisionId, toolName, args);
    } catch (e) {
      return this.#block(decisionId, toolName, 'internal_error', { detail: e instanceof Error ? e.message : String(e) });
    }
  }

  async #authorize(decisionId: string, toolName: string, args: ToolArguments): Promise<Authorization> {
    const { catalog, policy, prover } = this.#o;
    const target = this.#o.target ?? 'noir-recursive';

    if (!catalog.has(toolName)) {
      if (this.#passthrough.has(toolName)) {
        this.#emit({ decisionId, toolName, allowed: true, at: this.#clock() });
        return { allowed: true, protected: false, decisionId };
      }
      return this.#block(decisionId, toolName, 'unlisted_tool', { counts: false });
    }

    const now = this.#clock();
    if (now < this.#lockedUntil) return this.#block(decisionId, toolName, 'rate_limited', { counts: false });

    let unsealed;
    try {
      unsealed = catalog.resolve(toolName, args);
    } catch (e) {
      return this.#block(decisionId, toolName, 'malformed_arguments', { detail: e instanceof ActionMappingError ? e.message : undefined });
    }

    if (this.#o.registry !== undefined && (await this.#o.registry.status(policy.commitment)) !== 'active') {
      return this.#block(decisionId, toolName, 'policy_not_active', { action: unsealed, counts: false });
    }

    const action: Action = { ...unsealed, nonce: (this.#o.nonceSource ?? randomNonce)() };

    if (this.#o.precheck ?? true) {
      const violation = policy.check(action, now);
      if (violation !== undefined) return this.#block(decisionId, toolName, violation, { action: unsealed });
    }

    const inputs = policy.circuitInputs(this.#hasher, action, now);
    let proof;
    try {
      proof = await prover.prove({ inputs, target });
    } catch (e) {
      if (e instanceof ProofGenerationError && e.stage === 'witness') {
        return this.#block(decisionId, toolName, 'circuit_rejected', { action: unsealed, assertion: e.assertion, detail: e.message });
      }
      return this.#block(decisionId, toolName, 'proving_failed', { action: unsealed, detail: e instanceof Error ? e.message : String(e) });
    }

    // Verify for the public inputs built here, not the ones the prover returned: a prover (perhaps
    // remote) must not be able to substitute a proof of something else.
    const publicInputs = [policy.commitment, now, inputs.actionBinding] as const;
    if (proof.target !== target || !(await this.#self.verify(target, proof.proof, publicInputs))) {
      return this.#block(decisionId, toolName, 'self_verification_failed', { action: unsealed });
    }

    const envelope: IntentEnvelope = {
      target,
      policyCommitment: policy.commitment,
      currentTimestamp: now,
      nonce: action.nonce,
      proof: proof.proof,
    };
    this.#emit({ decisionId, toolName, allowed: true, action: unsealed, at: now });
    return { allowed: true, protected: true, decisionId, action, envelope };
  }

  #block(
    decisionId: string,
    toolName: string,
    reason: BlockReason,
    extra: { action?: Omit<Action, 'nonce'>; assertion?: CircuitAssertion | undefined; detail?: string | undefined; counts?: boolean } = {},
  ): Authorization {
    const at = this.#clock();
    if (extra.counts !== false) this.#countRefusal(at);
    this.#emit({
      decisionId,
      toolName,
      allowed: false,
      reason,
      at,
      ...(extra.action !== undefined ? { action: extra.action } : {}),
      ...(extra.assertion !== undefined ? { assertion: extra.assertion } : {}),
      ...(extra.detail !== undefined ? { detail: extra.detail } : {}),
    });
    return { allowed: false, decisionId, reason };
  }

  #countRefusal(at: bigint): void {
    const limit = this.#o.refusalLimit ?? DEFAULT_REFUSAL_LIMIT;
    if (limit === false) return;
    this.#refusals = this.#refusals.filter((t) => t + limit.windowSeconds > at);
    this.#refusals.push(at);
    if (this.#refusals.length >= limit.maxRefusals) {
      this.#lockedUntil = at + limit.lockoutSeconds;
      this.#refusals = [];
    }
  }

  #emit(d: FirewallDecision): void {
    try {
      this.#o.onDecision?.(d);
    } catch {
      // An audit hook must not change the decision.
    }
  }

  async destroy(): Promise<void> {
    if (this.#ownsSelf) await this.#self.destroy();
  }
}
