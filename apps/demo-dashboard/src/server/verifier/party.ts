/**
 * Everything the verifier party runs, wired together: the passkey-gated registry, IntentVerifier
 * over it, and the treasury tools. The tool-server process (main.ts) exposes this over IPC; tests
 * can also build it in-process.
 */
import { IntentVerifier, type ProofVerifier, type ReplayStore, InMemoryReplayStore } from '@zk-intent-firewall/mcp-firewall';
import type { ApprovalRequest, VerifierLogEntry } from '../../shared/api.ts';
import { TREASURY_SERVER_ID } from '../../shared/demo-config.ts';
import { INBOX, type InboxMessage } from '../../demo/inbox.ts';
import { treasuryCatalog } from '../tools.ts';
import { PasskeyPolicyRegistry } from './passkey-registry.ts';
import { Treasury } from './treasury.ts';

export interface VerifierConfig {
  readonly rpId: string;
  readonly rpName?: string;
  readonly expectedOrigins: readonly string[];
  readonly serverId?: string;
}

export interface VerifierPartyOptions extends VerifierConfig {
  readonly onEvent?: (entry: VerifierLogEntry) => void;
  readonly clock?: () => bigint;
  readonly proofVerifier?: ProofVerifier;
  readonly replayStore?: ReplayStore;
  readonly inbox?: readonly InboxMessage[];
}

export class VerifierParty {
  readonly registry: PasskeyPolicyRegistry;
  readonly verifier: IntentVerifier;
  readonly treasury: Treasury;

  private constructor(registry: PasskeyPolicyRegistry, verifier: IntentVerifier, treasury: Treasury) {
    this.registry = registry;
    this.verifier = verifier;
    this.treasury = treasury;
  }

  static async create(o: VerifierPartyOptions): Promise<VerifierParty> {
    const registry = new PasskeyPolicyRegistry({
      rpId: o.rpId,
      rpName: o.rpName ?? 'zk-intent-firewall demo',
      expectedOrigins: o.expectedOrigins,
      ...(o.clock ? { clock: o.clock } : {}),
    });
    const verifier = await IntentVerifier.create({
      catalog: treasuryCatalog(o.serverId ?? TREASURY_SERVER_ID),
      // IntentVerifier consults the passkey-gated registry on every call (spec 10.3 step 1).
      registry,
      replayStore: o.replayStore ?? new InMemoryReplayStore(),
      ...(o.proofVerifier ? { proofVerifier: o.proofVerifier } : {}),
      ...(o.clock ? { clock: o.clock } : {}),
    });
    const treasury = new Treasury({ verifier, inbox: o.inbox ?? INBOX, ...(o.onEvent ? { onEvent: o.onEvent } : {}), ...(o.clock ? { clock: o.clock } : {}) });
    return new VerifierParty(registry, verifier, treasury);
  }

  /** The RPC surface the host may call. None of it returns or accepts a policy opening. */
  rpcHandlers() {
    const r = this.registry;
    return {
      'enroll.options': () => r.enrollmentOptions(),
      'enroll.complete': (p: unknown) => r.completeEnrollment((p as { response?: unknown } | null)?.response),
      'approval.issue': (p: unknown) => {
        const q = (p ?? {}) as { action?: unknown; policyCommitment?: unknown };
        return r.issueApproval(q.action, q.policyCommitment);
      },
      'policy.register': (p: unknown) => r.approveRegistration(p as ApprovalRequest),
      'policy.revoke': (p: unknown) => r.approveRevocation(p as ApprovalRequest),
      'policy.records': (p: unknown) => {
        const list = (p as { commitments?: unknown } | null)?.commitments;
        return r.records(Array.isArray(list) ? list.filter((x): x is string => typeof x === 'string').slice(0, 100) : []);
      },
      'policy.status': (p: unknown) => {
        const c = (p as { policyCommitment?: unknown } | null)?.policyCommitment;
        return r.records(typeof c === 'string' ? [c] : [])[0]?.status ?? 'unknown';
      },
      'verifier.info': () => ({ rpId: r.rpId, ownerCredentialId: r.ownerCredentialId ?? null, vkHashes: r.vkHashes() }),
      ledger: () => [...this.treasury.ledger],
    } as const;
  }

  async destroy(): Promise<void> {
    await this.verifier.destroy();
  }
}
