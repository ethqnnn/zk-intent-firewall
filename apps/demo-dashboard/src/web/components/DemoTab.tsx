import { useState } from 'react';
import type { AgentStep, FirewallLogEntry, StateResponse, VerifierLogEntry } from '../../shared/api.ts';
import type { InboxMessage } from '../../demo/inbox.ts';
import type { RunView } from '../App.tsx';
import type { Api } from '../api.ts';
import { accountLabel, reasonText, short, usdc } from '../labels.ts';
import type { StoredPolicy } from '../storage.ts';
import type { RecordView } from './PolicyTab.tsx';
import { Badge, Button, Card, Mono, Notice, Spinner } from './ui.tsx';

interface Props {
  api: Api;
  state: StateResponse | undefined;
  policies: StoredPolicy[];
  records: Record<string, RecordView>;
  inbox: InboxMessage[];
  run: RunView | undefined;
}

const HOSTILE: Record<NonNullable<InboxMessage['hostile']>, string> = {
  redirect: 'Lookalike domain and wallet: redirects the payment',
  inflate: 'Hidden text for AI assistants: inflates the amount',
};

export function DemoTab({ api, state, policies, records, inbox, run }: Props) {
  const [ignoreRevocation, setIgnoreRevocation] = useState(false);
  const [fast, setFast] = useState(false);
  const [error, setError] = useState<string>();
  const [openMessage, setOpenMessage] = useState<string>();
  const armed = state?.firewall.armed ? state.firewall.policyCommitment : undefined;
  const armedPolicy = policies.find((p) => p.policyCommitment === armed);
  const running = state?.demo.running === true || (run !== undefined && !run.finished);

  const start = async () => {
    setError(undefined);
    try {
      await api.post('/api/demo/run', { paceMs: fast ? 0 : 700, firewallChecksRegistry: !ignoreRevocation });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.5fr)]">
      <div className="space-y-6">
        <Card title="The scenario" subtitle="An accounts-payable agent pays vendor invoices from an inbox an attacker can write to.">
          <p className="text-sm">
            The user tells the agent: <em>“Process the accounts-payable inbox and pay every vendor invoice that is due.”</em> The agent is scripted to fail the
            way language models do under prompt injection: it believes a remittance change from a lookalike domain, and it obeys text addressed to AI
            assistants.
          </p>
          <ul className="mt-4 space-y-2" data-testid="inbox">
            {inbox.map((m) => (
              <li key={m.id} className="rounded-lg border border-slate-200 dark:border-slate-800">
                <button className="w-full px-3 py-2 text-left" onClick={() => setOpenMessage(openMessage === m.id ? undefined : m.id)} aria-expanded={openMessage === m.id}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{m.subject}</span>
                    {m.hostile ? <Badge tone="warn">injection</Badge> : <Badge>legitimate</Badge>}
                  </div>
                  <div className="truncate text-xs text-slate-500 dark:text-slate-400">{m.from}</div>
                  {m.hostile && <div className="mt-1 text-xs text-amber-700 dark:text-amber-400">{HOSTILE[m.hostile]}</div>}
                </button>
                {openMessage === m.id && <pre className="mono max-h-72 overflow-auto border-t border-slate-100 px-3 py-2 text-xs whitespace-pre-wrap dark:border-slate-800">{m.body}</pre>}
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Run">
          {!armed ? (
            <Notice tone="warn">Approve a policy with your passkey and arm the firewall first (Policy & passkey tab).</Notice>
          ) : (
            <div className="space-y-3 text-sm">
              <p>
                Firewall armed with <strong>{armedPolicy?.name ?? 'a policy'}</strong>
                {records[armed] && (
                  <>
                    {' '}
                    <Badge tone={records[armed]!.status === 'active' ? 'good' : 'bad'}>{records[armed]!.status}</Badge>
                  </>
                )}
                {armedPolicy && (
                  <span className="block text-slate-500 dark:text-slate-400">
                    Limit {armedPolicy.definition.maxAmountUsdc} USDC per payment, {armedPolicy.definition.payees.length} payees.
                  </span>
                )}
              </p>
              <label className="flex items-start gap-2">
                <input type="checkbox" className="mt-0.5" checked={ignoreRevocation} onChange={(e) => setIgnoreRevocation(e.target.checked)} data-testid="ignore-revocation" />
                <span>
                  Simulate a firewall that ignores revocation
                  <span className="block text-xs text-slate-500 dark:text-slate-400">It keeps proving under a revoked policy; the verifier must refuse on its own.</span>
                </span>
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={fast} onChange={(e) => setFast(e.target.checked)} />
                <span>Fast (no pauses between steps)</span>
              </label>
              <Button testId="run-demo" onClick={() => void start()} disabled={running}>
                {running && <Spinner />} {running ? 'Running…' : 'Run the agent'}
              </Button>
              {error && <Notice tone="bad">{error}</Notice>}
            </div>
          )}
        </Card>
      </div>

      <Card title="What happened" subtitle={run ? (run.finished ? 'Run finished.' : 'Running live: every proof below is real and verified by a separate process.') : 'Run the agent to see each call.'}>
        {run ? <Timeline run={run} policies={policies} /> : <p className="text-sm text-slate-500 dark:text-slate-400">Nothing yet.</p>}
      </Card>
    </div>
  );
}

function Timeline({ run, policies }: { run: RunView; policies: StoredPolicy[] }) {
  const results = new Map(run.steps.filter((s): s is Extract<AgentStep, { kind: 'tool_result' }> => s.kind === 'tool_result').map((s) => [s.callId, s]));
  const payments = run.steps.filter((s): s is Extract<AgentStep, { kind: 'tool_call' }> => s.kind === 'tool_call' && s.tool === 'send_payment');
  const executed = payments.filter((p) => run.verifier[p.callId]?.outcome === 'executed').length;
  const blocked = payments.filter((p) => run.firewall[p.callId]?.allowed === false).length;
  const refused = payments.filter((p) => run.verifier[p.callId]?.outcome === 'rejected').length;

  return (
    <div>
      <ol className="space-y-3" data-testid="timeline">
        {run.steps.map((s, i) => {
          if (s.kind === 'instruction')
            return (
              <li key={i} className="enter rounded-lg bg-slate-100 px-3 py-2 text-sm dark:bg-slate-800">
                <span className="text-xs font-semibold tracking-wide text-slate-500 uppercase">User</span>
                <p>{s.text}</p>
              </li>
            );
          if (s.kind === 'thought')
            return (
              <li key={i} className={`enter flex gap-2 text-sm ${s.flagged ? 'rounded-lg bg-amber-50 px-3 py-2 text-amber-900 ring-1 ring-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:ring-amber-900' : 'px-1 text-slate-600 dark:text-slate-300'}`}>
                <span className="shrink-0 font-semibold">{s.flagged ? 'Agent, injected:' : 'Agent:'}</span>
                <span>{s.text}</span>
              </li>
            );
          if (s.kind === 'tool_call')
            return s.tool === 'send_payment' ? (
              <PaymentCard key={i} call={s} result={results.get(s.callId)} fw={run.firewall[s.callId]} vf={run.verifier[s.callId]} policies={policies} />
            ) : (
              <li key={i} className="enter px-1 text-xs text-slate-500 dark:text-slate-400">
                <Mono>
                  {s.tool}({Object.values(s.args).join(', ')})
                </Mono>{' '}
                · read-only, passed through without a proof
              </li>
            );
          if (s.kind === 'done')
            return (
              <li key={i} className="enter px-1 text-sm font-medium">
                {s.text}
              </li>
            );
          return null;
        })}
      </ol>
      {run.finished && (
        <div className="mt-5 flex flex-wrap gap-2 border-t border-slate-100 pt-4 dark:border-slate-800" data-testid="run-summary">
          <Badge tone="good">{executed} paid with a verified proof</Badge>
          <Badge tone="bad">{blocked} blocked by the firewall</Badge>
          {refused > 0 && <Badge tone="bad">{refused} refused by the verifier</Badge>}
          {run.finished.error && <Badge tone="bad">error: {run.finished.error}</Badge>}
        </div>
      )}
    </div>
  );
}

function PaymentCard({
  call,
  result,
  fw,
  vf,
  policies,
}: {
  call: Extract<AgentStep, { kind: 'tool_call' }>;
  result: Extract<AgentStep, { kind: 'tool_result' }> | undefined;
  fw: FirewallLogEntry | undefined;
  vf: VerifierLogEntry | undefined;
  policies: StoredPolicy[];
}) {
  const args = call.args as { recipient?: string; amount?: string };
  const outcome = !fw ? 'pending' : !fw.allowed ? 'blocked' : !vf ? 'forwarding' : vf.outcome === 'executed' ? 'paid' : 'rejected';
  const tone = outcome === 'paid' ? 'good' : outcome === 'blocked' || outcome === 'rejected' ? 'bad' : 'neutral';
  const border = { good: 'border-emerald-300 dark:border-emerald-800', bad: 'border-rose-300 dark:border-rose-800', neutral: 'border-slate-200 dark:border-slate-800' }[tone];
  return (
    <li className={`enter rounded-lg border-l-4 border ${border} bg-white px-4 py-3 dark:bg-slate-900`} data-testid="payment-card" data-outcome={outcome}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm">
          <span className="font-semibold">send_payment</span> {usdc(args.amount)} to <strong>{accountLabel(args.recipient, policies)}</strong>{' '}
          <Mono title={args.recipient}>{short(args.recipient ?? '')}</Mono>
        </div>
        <Badge tone={tone}>{outcome === 'pending' ? 'proving…' : outcome}</Badge>
      </div>
      <dl className="mt-2 grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-1 text-sm">
        <dt className="text-slate-500">Firewall</dt>
        <dd>
          {!fw ? (
            <span className="inline-flex items-center gap-1.5 text-slate-500">
              <Spinner /> generating a zero-knowledge proof…
            </span>
          ) : fw.allowed ? (
            <span className="text-emerald-700 dark:text-emerald-400">Proof generated in {fw.elapsedMs} ms</span>
          ) : (
            <span className="text-rose-700 dark:text-rose-400">
              Blocked: {reasonText(fw.reason)}
              {fw.assertion && <span className="text-slate-500"> (circuit: “{fw.assertion}”)</span>}
            </span>
          )}
        </dd>
        <dt className="text-slate-500">Verifier</dt>
        <dd>
          {fw && !fw.allowed ? (
            <span className="text-slate-500">Never received the call</span>
          ) : !vf ? (
            <span className="text-slate-500">…</span>
          ) : vf.outcome === 'executed' ? (
            <span className="text-emerald-700 dark:text-emerald-400">
              Proof verified in {vf.verifyMs} ms ({vf.proofBytes?.toLocaleString()} bytes, {vf.target}); payment executed
            </span>
          ) : (
            <span className="text-rose-700 dark:text-rose-400">Rejected: {reasonText(vf.reason)}</span>
          )}
        </dd>
        {result && (
          <>
            <dt className="text-slate-500">Agent saw</dt>
            <dd className="text-slate-600 dark:text-slate-300">{result.text}</dd>
          </>
        )}
      </dl>
    </li>
  );
}
