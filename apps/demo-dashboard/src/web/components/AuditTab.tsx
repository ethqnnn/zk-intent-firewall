import type { LogResponse } from '../../shared/api.ts';
import { accountLabel, reasonText, short, time, usdc } from '../labels.ts';
import type { StoredPolicy } from '../storage.ts';
import { Badge, Button, Card, Mono, Notice } from './ui.tsx';

export function AuditTab({ log, policies, onRefresh }: { log: LogResponse | undefined; policies: StoredPolicy[]; onRefresh: () => Promise<void> }) {
  const decisions = [...(log?.firewall ?? [])].reverse();
  return (
    <div className="space-y-6">
      <Notice tone="neutral">
        Fed by the firewall's <Mono>onDecision</Mono> hook. Each entry keeps a fixed set of fields: the call, the decision and the reason. No policy value (limit,
        payees, scopes, expiry or salt) is ever written here, and the agent sees none of it, only an opaque decision ID.
      </Notice>
      <Card title="Firewall decisions" subtitle="Prover side, before anything leaves the agent's side." actions={<Button variant="secondary" onClick={() => void onRefresh()}>Refresh</Button>}>
        {decisions.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">No decisions yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm" data-testid="audit-table">
              <thead className="text-xs text-slate-500 uppercase">
                <tr>
                  <th className="py-2 pr-3 font-medium">Time</th>
                  <th className="py-2 pr-3 font-medium">Tool</th>
                  <th className="py-2 pr-3 font-medium">Decision</th>
                  <th className="py-2 pr-3 font-medium">Amount</th>
                  <th className="py-2 pr-3 font-medium">Recipient</th>
                  <th className="py-2 pr-3 font-medium">Why</th>
                  <th className="py-2 font-medium">Decision ID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {decisions.map((d) => (
                  <tr key={d.decisionId}>
                    <td className="py-2 pr-3 whitespace-nowrap">{time(d.at)}</td>
                    <td className="py-2 pr-3">
                      <Mono>{d.tool}</Mono>
                    </td>
                    <td className="py-2 pr-3">{d.allowed ? <Badge tone="good">allowed</Badge> : <Badge tone="bad">blocked</Badge>}</td>
                    <td className="py-2 pr-3 whitespace-nowrap">{d.requested?.amount ? usdc(d.requested.amount) : ''}</td>
                    <td className="py-2 pr-3">
                      {d.requested?.recipient && (
                        <>
                          {accountLabel(d.requested.recipient, policies)} <Mono>{short(d.requested.recipient)}</Mono>
                        </>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      {d.allowed ? (d.action ? `proof in ${d.elapsedMs} ms` : 'read-only') : reasonText(d.reason)}
                      {d.assertion && <span className="text-slate-500"> (circuit: {d.assertion})</span>}
                    </td>
                    <td className="py-2">
                      <Mono>{d.decisionId.slice(0, 8)}</Mono>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Executed payments" subtitle="The treasury's ledger: only calls whose proof the verifier accepted.">
        {(log?.ledger.length ?? 0) === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">No payments.</p>
        ) : (
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800" data-testid="ledger">
            {log!.ledger.map((l, i) => (
              <li key={i} className="flex flex-wrap justify-between gap-2 py-2">
                <span>
                  {usdc(l.amount)} to {accountLabel(l.recipient, policies)} <Mono>{short(l.recipient)}</Mono>
                </span>
                <span className="text-slate-500">{time(l.at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
