import type { LogResponse, StateResponse } from '../../shared/api.ts';
import { accountLabel, reasonText, short, shortHex, time, usdc } from '../labels.ts';
import type { StoredPolicy } from '../storage.ts';
import type { RecordView } from './PolicyTab.tsx';
import { Badge, Card, Mono } from './ui.tsx';

export function VerifierTab({ log, state, policies, records }: { log: LogResponse | undefined; state: StateResponse | undefined; policies: StoredPolicy[]; records: Record<string, RecordView> }) {
  const calls = [...(log?.verifier ?? [])].filter((v) => v.outcome !== 'served').reverse();
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <Card title="What the treasury verifier received" subtitle="Per payment: the call itself, the proof and three public inputs it rebuilt on its own.">
        {calls.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">No payment calls have reached the verifier yet.</p>
        ) : (
          <ul className="space-y-3" data-testid="verifier-calls">
            {calls.map((v, i) => (
              <li key={i} className="rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-800">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span>
                    <Mono>{v.tool}</Mono> {v.payment && <>· {usdc(v.payment.amount)} to {accountLabel(v.payment.recipient, policies)}</>}
                  </span>
                  {v.outcome === 'executed' ? <Badge tone="good">verified · executed</Badge> : <Badge tone="bad">rejected: {reasonText(v.reason)}</Badge>}
                </div>
                <dl className="mt-2 grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 text-xs">
                  {v.publicInputs && (
                    <>
                      <dt className="text-slate-500">policy_commitment</dt>
                      <dd>
                        <Mono>{v.publicInputs.policyCommitment}</Mono>
                      </dd>
                      <dt className="text-slate-500">current_timestamp</dt>
                      <dd>
                        <Mono>{v.publicInputs.currentTimestamp}</Mono> ({time(v.publicInputs.currentTimestamp)})
                      </dd>
                      <dt className="text-slate-500">action_binding</dt>
                      <dd>
                        <Mono>{v.publicInputs.actionBinding}</Mono>
                      </dd>
                    </>
                  )}
                  {v.proofBytes !== undefined && (
                    <>
                      <dt className="text-slate-500">proof</dt>
                      <dd>
                        {v.proofBytes.toLocaleString()} bytes, UltraHonk ({v.target}, zero-knowledge){v.verifyMs !== undefined && `, verified in ${v.verifyMs} ms`}
                      </dd>
                    </>
                  )}
                  {v.payment && (
                    <>
                      <dt className="text-slate-500">recipient</dt>
                      <dd>
                        <Mono>{short(v.payment.recipient)}</Mono>
                      </dd>
                    </>
                  )}
                </dl>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <div className="space-y-6">
        <Card title="Never received">
          <ul className="list-disc space-y-1 pl-5 text-sm">
            <li>The per-payment limit</li>
            <li>The allowlist, beyond the one payee of each payment</li>
            <li>Which other actions the policy grants</li>
            <li>The expiry</li>
            <li>The salt</li>
          </ul>
          <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
            The proof is zero-knowledge and the commitment is salted, so none of these can be recovered from what is shown here.
          </p>
        </Card>
        <Card title="Verifier registry" subtitle="Commitments activated by your passkey.">
          <ul className="space-y-2 text-sm" data-testid="registry">
            {Object.values(records).map((r) => (
              <li key={r.policyCommitment} className="flex items-center justify-between gap-2">
                <Mono title={r.policyCommitment}>{shortHex(r.policyCommitment)}</Mono>
                <Badge tone={r.status === 'active' ? 'good' : r.status === 'revoked' ? 'bad' : 'neutral'}>{r.status}</Badge>
              </li>
            ))}
          </ul>
          {state && (
            <dl className="mt-4 space-y-1 text-xs">
              <dt className="text-slate-500">Approvals must cover</dt>
              <dd>
                <Mono>{state.verifier.approvalLabel}</Mono>
              </dd>
              {Object.entries(state.verifier.vkHashes).map(([t, h]) => (
                <dd key={t}>
                  <Mono>
                    vk_hash.{t}: {shortHex(h)}
                  </Mono>
                </dd>
              ))}
            </dl>
          )}
        </Card>
      </div>
    </div>
  );
}
