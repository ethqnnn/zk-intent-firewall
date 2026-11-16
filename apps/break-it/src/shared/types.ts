/**
 * What the engine process and the front process exchange, and what the public API returns. Plain
 * JSON only: amounts and field elements are strings.
 */
import type { LedgerSnapshot } from '../engine/ledger.ts';

export type AttemptRoute = 'agent' | 'direct' | 'passkey' | 'enroll';

/** Where a refusal came from. */
export type CheckLayer =
  /** IntentFirewall, before or instead of proving (spec 10.2). */
  | 'firewall'
  /** The circuit itself refused the witness (spec section 7 assertions). */
  | 'circuit'
  /** The MCP tool server's input schema, before any handler ran. */
  | 'mcp-schema'
  /** IntentVerifier, the spec 10.3 checklist. */
  | 'verifier'
  /** PasskeyPolicyRegistry: enrolment and approval checks. */
  | 'passkey-registry'
  /** The fake ledger (insufficient funds), after the verifier accepted. */
  | 'ledger'
  /** The request itself was not understood. */
  | 'request';

export interface CaughtBy {
  readonly layer: CheckLayer;
  /** The named check, for example `recipient_not_allowlisted` or `invalid_proof`. */
  readonly check: string;
  /** The circuit assertion message, when the circuit refused. */
  readonly assertion?: string;
}

/**
 * - `caught`: a check refused it.
 * - `legitimate`: it was inside the published policy and went through, as it should.
 * - `break`: something was accepted that the published policy does not allow. A real finding.
 */
export type Verdict = 'caught' | 'legitimate' | 'break';

export type AttemptResult =
  /** The firewall refused to prove; nothing was forwarded. */
  | 'blocked'
  /** The tool server, the verifier or the registry refused. */
  | 'rejected'
  /** A payment executed on the fake ledger. */
  | 'executed'
  /** A read-only tool answered. */
  | 'served'
  /** The firewall produced a proof and handed it back without spending it. */
  | 'proof_issued'
  /** A passkey approval or enrolment was accepted. */
  | 'approved'
  | 'invalid_request';

export interface EnvelopeSummary {
  readonly target?: string;
  readonly policy_commitment?: string;
  readonly current_timestamp?: string;
  readonly nonce?: string;
  readonly proofBytes?: number;
  /** First 16 hex digits of SHA-256 of the proof bytes, to spot reuse without storing proofs. */
  readonly proofSha256?: string;
  /** Set when the envelope is not even an object of the expected shape. */
  readonly malformed?: true;
}

/** What was attempted, as recorded. Long values are truncated. */
export interface AttemptSummary {
  readonly tool?: string;
  /** JSON of the arguments, at most 600 characters. */
  readonly arguments?: string;
  readonly mode?: 'forward' | 'prove-only';
  readonly precheck?: boolean;
  readonly envelope?: EnvelopeSummary | null;
  /** Other `_meta` keys sent, by name. */
  readonly metaKeys?: readonly string[];
  readonly passkey?: {
    readonly action?: string;
    readonly policyCommitment?: string;
    readonly credentialId?: string;
    readonly stage?: string;
  };
}

/** What the engine reports for one attempt. The front adds identity, time and id. */
export interface AttemptDraft {
  readonly route: AttemptRoute;
  readonly attempted: AttemptSummary;
  readonly result: AttemptResult;
  readonly caughtBy: CaughtBy | null;
  readonly verdict: Verdict;
  /** Why the break detector called it a break. */
  readonly breakReasons?: readonly string[];
  readonly payment?: { readonly tool: string; readonly recipient: string; readonly amount: string; readonly reference: string };
  readonly ms: number;
}

export interface AttemptRecord extends AttemptDraft {
  readonly id: string;
  /** ISO 8601. */
  readonly at: string;
  /** The published policy commitment at the time: identifies the instance's lifetime. */
  readonly policyCommitment: string;
  /** A chosen handle, or `anon-` and a per-instance pseudonym. Never an IP address. */
  readonly who: string;
  readonly note?: string;
}

/** An engine answer to one attempt. */
export interface EngineAnswer {
  readonly http: number;
  readonly response: Readonly<Record<string, unknown>>;
  readonly draft?: AttemptDraft;
}

export interface PublicPolicyView {
  readonly policyCommitment: string;
  readonly maxAmount: string;
  readonly allowlist: readonly { readonly label: string; readonly account: string }[];
  readonly grantedScopes: readonly string[];
  readonly expiry: string;
  readonly expiresAt: string;
  readonly salt: 'secret';
}

export interface StatusView {
  readonly startedAt: string;
  readonly policy: PublicPolicyView;
  readonly asset: { readonly id: string; readonly decimals: number; readonly unit: string };
  readonly tools: readonly { readonly name: string; readonly protected: boolean; readonly scope?: string; readonly granted?: boolean; readonly description: string }[];
  readonly notAllowlisted: readonly { readonly label: string; readonly account: string }[];
  readonly verifier: {
    readonly serverId: string;
    readonly rpId: string;
    readonly origin: string;
    readonly ownerCredentialId: string | null;
    readonly vkHashes: Readonly<Record<string, string>>;
    readonly freshness: { readonly maxAgeSeconds: number; readonly maxFutureSkewSeconds: number };
    readonly registry: { readonly status: string };
  };
  readonly firewall: { readonly refusalLimit: { readonly maxRefusals: number; readonly windowSeconds: number; readonly lockoutSeconds: number } };
  readonly ledger: LedgerSnapshot;
}
