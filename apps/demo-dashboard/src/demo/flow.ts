/**
 * The demo as a script: enrol the owner's passkey, author the policy, approve it, arm the
 * firewall, run the agent, and optionally revoke and run again. The headless CLI and the
 * integration tests use it with the software authenticator; the dashboard does the same steps
 * with a real passkey, and the Playwright test drives those steps through the browser.
 */
import type { ApprovalAction } from '../shared/approval.ts';
import { encodeStatement, statementChallenge } from '../shared/approval.ts';
import type { ApprovalResult, PreparePolicyResponse, RunRequest } from '../shared/api.ts';
import { DEMO_POLICY_PRESET, type ScopeName, USDC_DECIMALS } from '../shared/demo-config.ts';
import { toBaseUnits } from '../shared/units.ts';
import type { Host, RunResult } from '../server/host/host.ts';
import type { SoftAuthenticator } from './soft-authenticator.ts';

export interface PolicyInput {
  readonly maxAmountUsdc: string;
  readonly payees: readonly string[];
  readonly scopes: readonly ScopeName[];
  /** Unix seconds. */
  readonly expiry: bigint;
}

export function presetPolicy(now: bigint = BigInt(Math.floor(Date.now() / 1000))): PolicyInput {
  return {
    maxAmountUsdc: DEMO_POLICY_PRESET.maxAmountUsdc,
    payees: DEMO_POLICY_PRESET.payees.map((p) => p.account),
    scopes: DEMO_POLICY_PRESET.scopes,
    expiry: now + BigInt(DEMO_POLICY_PRESET.validForDays) * 86_400n,
  };
}

/** A non-zero 248-bit salt from the CSPRNG, as the browser draws it. */
export function randomSaltHex(): string {
  for (;;) {
    const b = globalThis.crypto.getRandomValues(new Uint8Array(31));
    const hex = Buffer.from(b).toString('hex');
    if (BigInt('0x' + hex) >= 1n << 128n) return '0x' + hex;
  }
}

export async function enrol(host: Host, auth: SoftAuthenticator): Promise<string> {
  const options = (await host.passkeyOptions()) as { challenge: string };
  const r = await host.passkeyComplete(auth.createRegistrationResponse(options));
  if (!r.ok) throw new Error(`enrolment refused: ${r.reason} ${r.detail ?? ''}`);
  return r.credentialId;
}

export async function preparePolicy(host: Host, p: PolicyInput): Promise<PreparePolicyResponse> {
  return host.preparePolicy({
    maxAmount: toBaseUnits(p.maxAmountUsdc, USDC_DECIMALS).toString(),
    recipients: p.payees,
    scopes: p.scopes,
    expiry: p.expiry.toString(),
    salt: randomSaltHex(),
  });
}

/**
 * Asks the verifier for a challenge, checks it is the statement we mean to sign (as the dashboard
 * does), signs it with the authenticator and submits it.
 */
export async function approve(host: Host, auth: SoftAuthenticator, action: ApprovalAction, policyCommitment: string): Promise<ApprovalResult> {
  const ch = await host.approvalChallenge({ action, policyCommitment });
  const text = encodeStatement(ch.statement);
  if (ch.statement.action !== action || ch.statement.policyCommitment !== policyCommitment || text !== ch.statementText || (await statementChallenge(ch.statement)) !== ch.challenge) {
    throw new Error('the verifier asked to sign something other than this approval');
  }
  const response = auth.createAssertion(ch.challenge);
  const req = { policyCommitment, nonce: ch.statement.nonce, response };
  return action === 'register' ? host.registerPolicy(req) : host.revokePolicy(req);
}

export interface DemoSetup {
  readonly policy: PreparePolicyResponse;
}

/** Enrols (if needed), authors, approves and arms the preset policy, or `policy` if given. */
export async function setUpDemo(host: Host, auth: SoftAuthenticator, policy: PolicyInput = presetPolicy()): Promise<DemoSetup> {
  if (!(await host.state()).passkey.enrolled) await enrol(host, auth);
  const prepared = await preparePolicy(host, policy);
  const r = await approve(host, auth, 'register', prepared.policyCommitment);
  if (!r.ok) throw new Error(`registration refused: ${r.reason} ${r.detail ?? ''}`);
  await host.arm(prepared.opening);
  return { policy: prepared };
}

export function runDemo(host: Host, options: RunRequest = {}): Promise<RunResult> {
  return host.runDemo(options);
}
