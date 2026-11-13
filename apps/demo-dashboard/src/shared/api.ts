/**
 * The HTTP API between the dashboard (browser) and the host, and the events the host streams. Both
 * sides import these types; nothing here is executable except constants.
 */
import type { ApprovalAction, ApprovalStatement } from './approval.ts';
import type { ScopeName } from './demo-config.ts';

/** Request header carrying the session token. */
export const SESSION_HEADER = 'x-zkif-session';

/**
 * The policy opening as stored by the dashboard and sent to arm the firewall. Same shape as
 * PolicyOpeningJson in packages/mcp-firewall. It contains the salt: it is the secret.
 */
export interface PolicyOpeningWire {
  readonly version: 1;
  readonly maxAmount: string;
  readonly recipients: readonly string[];
  readonly allowlistOrder: 'sorted' | 'insertion';
  readonly scopes: readonly number[];
  readonly expiry: string;
  readonly salt: string;
}

export interface StateResponse {
  readonly passkey: { readonly enrolled: boolean; readonly credentialId?: string };
  readonly firewall: { readonly armed: false } | { readonly armed: true; readonly policyCommitment: string };
  readonly verifier: {
    readonly serverId: string;
    readonly rpId: string;
    readonly approvalLabel: string;
    readonly vkHashes: Readonly<Record<string, string>>;
  };
  readonly demo: { readonly running: boolean };
}

export interface PreparePolicyRequest {
  /** u128 base units, decimal. */
  readonly maxAmount: string;
  /** CAIP-10 accounts of the payees. */
  readonly recipients: readonly string[];
  readonly scopes: readonly ScopeName[];
  /** Unix seconds, decimal. */
  readonly expiry: string;
  /** 0x hex, drawn by the browser's CSPRNG. */
  readonly salt: string;
}

export interface PreparePolicyResponse {
  readonly opening: PolicyOpeningWire;
  readonly policyCommitment: string;
}

export interface ChallengeRequest {
  readonly action: ApprovalAction;
  readonly policyCommitment: string;
}

export interface ChallengeResponse {
  readonly statement: ApprovalStatement;
  readonly statementText: string;
  readonly challenge: string;
  readonly rpId: string;
  readonly allowCredentials: readonly { readonly id: string; readonly type: 'public-key'; readonly transports?: readonly string[] }[];
  readonly timeoutMs: number;
}

export interface ApprovalRequest {
  readonly policyCommitment: string;
  readonly nonce: string;
  /** The AuthenticationResponseJSON from navigator.credentials.get. */
  readonly response: unknown;
}

export type CommitmentStatus = 'active' | 'revoked' | 'unknown';

export type ApprovalRejection =
  | 'malformed_request'
  | 'no_owner_enrolled'
  | 'unknown_nonce'
  | 'nonce_expired'
  | 'nonce_mismatch'
  | 'unknown_credential'
  | 'signature_invalid'
  | 'commitment_revoked';

export type ApprovalResult =
  | { readonly ok: true; readonly status: CommitmentStatus }
  | { readonly ok: false; readonly reason: ApprovalRejection; readonly detail?: string };

export type EnrollmentResult = { readonly ok: true; readonly credentialId: string } | { readonly ok: false; readonly reason: string; readonly detail?: string };

export interface RunRequest {
  /** Pause between agent steps, in milliseconds. */
  readonly paceMs?: number;
  /**
   * Default true. False simulates a firewall that never consults the verifier's registry, to show
   * that revocation is enforced by the verifier itself.
   */
  readonly firewallChecksRegistry?: boolean;
}

// ---------------------------------------------------------------------------------------------
// Events

export type AgentStep =
  | { readonly kind: 'instruction'; readonly text: string }
  | { readonly kind: 'thought'; readonly text: string; readonly flagged?: boolean }
  | { readonly kind: 'tool_call'; readonly callId: string; readonly tool: string; readonly args: Readonly<Record<string, unknown>> }
  | { readonly kind: 'tool_result'; readonly callId: string; readonly isError: boolean; readonly text: string }
  | { readonly kind: 'done'; readonly text: string };

/**
 * One firewall decision as the operator's audit log keeps it. Built from FirewallDecision by an
 * allowlist of fields: no policy value (limit, allowlist, scope mask, expiry, salt) ever enters it.
 */
export interface FirewallLogEntry {
  readonly decisionId: string;
  readonly callId?: string;
  readonly tool: string;
  readonly allowed: boolean;
  readonly reason?: string;
  readonly assertion?: string;
  /** What the agent asked for, as it asked for it. */
  readonly requested?: { readonly recipient?: string; readonly amount?: string };
  /** The circuit action, without the nonce. */
  readonly action?: { readonly toolId: string; readonly scopeIndex: number; readonly amount: string; readonly recipient: string };
  /** Unix seconds. */
  readonly at: string;
  /** Time from the call reaching the firewall to the decision, including proving. */
  readonly elapsedMs?: number;
}

/** What the tool server did with one call. */
export interface VerifierLogEntry {
  readonly callId?: string;
  readonly tool: string;
  readonly outcome: 'executed' | 'rejected' | 'served';
  readonly reason?: string;
  readonly target?: string;
  readonly proofBytes?: number;
  readonly publicInputs?: { readonly policyCommitment: string; readonly currentTimestamp: string; readonly actionBinding: string };
  readonly verifyMs?: number;
  readonly payment?: { readonly recipient: string; readonly amount: string };
  /** Unix seconds. */
  readonly at: string;
}

export type HostEvent =
  | { readonly type: 'run_started'; readonly runId: string; readonly options: Required<RunRequest> }
  | { readonly type: 'agent'; readonly runId: string; readonly step: AgentStep }
  | { readonly type: 'firewall'; readonly runId?: string; readonly entry: FirewallLogEntry }
  | { readonly type: 'verifier'; readonly runId?: string; readonly entry: VerifierLogEntry }
  | { readonly type: 'run_finished'; readonly runId: string; readonly exitCode: number | null; readonly error?: string }
  | { readonly type: 'registry'; readonly policyCommitment: string; readonly status: CommitmentStatus }
  | { readonly type: 'firewall_armed'; readonly policyCommitment: string }
  | { readonly type: 'firewall_disarmed' };

export interface LogResponse {
  readonly firewall: readonly FirewallLogEntry[];
  readonly verifier: readonly VerifierLogEntry[];
  readonly ledger: readonly { readonly recipient: string; readonly amount: string; readonly at: string }[];
}
