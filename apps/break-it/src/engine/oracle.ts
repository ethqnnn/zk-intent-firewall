/**
 * The break detector. It judges every payment the verifier accepted, and every proof the firewall
 * issued, against the published policy, with its own plain checks: no circuit, no hashing, no
 * ToolCatalog, no PolicyOpening. If the zero-knowledge path accepts something these few lines
 * refuse, that is a genuine break, and it is flagged in the public log.
 *
 * What it calls a break:
 *   - an accepted action whose tool needs a scope the policy does not grant;
 *   - an accepted action with arguments other than recipient and amount;
 *   - a recipient that is not exactly one of the allowlisted accounts;
 *   - an amount of zero or above the limit, or a paid amount that differs from the requested one;
 *   - an accepted action at or after the policy's expiry;
 *   - an accepted action under any commitment other than the published one;
 *   - the same (commitment, action binding) executed twice.
 */

export interface PublishedPolicy {
  /** 0x followed by 64 lowercase hex digits. */
  readonly policyCommitment: string;
  /** Base units. */
  readonly maxAmount: bigint;
  /** CAIP-10 accounts, `eip155:<chain>:0x<40 lowercase hex>`. */
  readonly allowlist: readonly string[];
  /** Tools whose scope the policy grants. */
  readonly grantedTools: readonly string[];
  /** Unix seconds. Valid strictly before. */
  readonly expiry: bigint;
}

export interface JudgedAction {
  readonly tool: string;
  readonly arguments: unknown;
  readonly policyCommitment: string;
  /** Unix seconds: the proof's timestamp. */
  readonly at: bigint;
  /** What was actually paid, when a payment executed. */
  readonly paidAmount?: bigint;
}

const ALLOWED_ARGS = new Set(['recipient', 'amount']);
const CAIP10 = /^eip155:([1-9][0-9]{0,15}):0x([0-9a-fA-F]{40})$/;
const BARE = /^0x([0-9a-fA-F]{40})$/;
const MAX_SEEN = 200_000;

function account(x: unknown): string | undefined {
  if (typeof x !== 'string') return undefined;
  const s = x.trim();
  const c = CAIP10.exec(s);
  if (c) return `eip155:${c[1]}:0x${c[2]!.toLowerCase()}`;
  const b = BARE.exec(s);
  return b ? `eip155:1:0x${b[1]!.toLowerCase()}` : undefined;
}

function amount(x: unknown): bigint | undefined {
  if (typeof x === 'number' && Number.isSafeInteger(x) && x >= 0) return BigInt(x);
  if (typeof x === 'string' && /^(0|[1-9][0-9]{0,38})$/.test(x)) return BigInt(x);
  return undefined;
}

export class PolicyOracle {
  readonly policy: PublishedPolicy;
  readonly #allow: ReadonlySet<string>;
  readonly #granted: ReadonlySet<string>;
  readonly #executed = new Set<string>();

  constructor(policy: PublishedPolicy) {
    this.policy = policy;
    this.#allow = new Set(policy.allowlist);
    this.#granted = new Set(policy.grantedTools);
  }

  /** Why the published policy does not allow this action. Empty when it does. */
  violations(a: JudgedAction): string[] {
    const out: string[] = [];
    if (a.policyCommitment !== this.policy.policyCommitment) out.push('not_the_published_policy_commitment');
    if (!this.#granted.has(a.tool)) out.push('tool_scope_not_granted');
    const args = typeof a.arguments === 'object' && a.arguments !== null && !Array.isArray(a.arguments) ? (a.arguments as Record<string, unknown>) : undefined;
    if (!args) {
      out.push('arguments_not_an_object');
      return out;
    }
    if (Object.keys(args).some((k) => !ALLOWED_ARGS.has(k))) out.push('arguments_not_bound_by_the_proof');
    const to = account(args['recipient']);
    if (to === undefined) out.push('recipient_unparseable');
    else if (!this.#allow.has(to)) out.push('recipient_not_allowlisted');
    const amt = amount(args['amount']);
    if (amt === undefined) out.push('amount_unparseable');
    else {
      if (amt === 0n) out.push('amount_zero');
      if (amt > this.policy.maxAmount) out.push('amount_exceeds_limit');
      if (a.paidAmount !== undefined && a.paidAmount !== amt) out.push('paid_amount_differs_from_requested');
    }
    if (a.paidAmount !== undefined && a.paidAmount > this.policy.maxAmount) out.push('paid_amount_exceeds_limit');
    if (a.at >= this.policy.expiry) out.push('policy_expired');
    return [...new Set(out)];
  }

  /**
   * Records an executed (commitment, binding) pair and reports a second execution of one. The
   * verifier's replay store is supposed to make this impossible.
   */
  executedTwice(policyCommitment: string, actionBinding: string): boolean {
    const key = `${policyCommitment}:${actionBinding}`;
    if (this.#executed.has(key)) return true;
    if (this.#executed.size >= MAX_SEEN) this.#executed.clear();
    this.#executed.add(key);
    return false;
  }
}
