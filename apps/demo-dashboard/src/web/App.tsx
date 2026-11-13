import { useCallback, useEffect, useMemo, useState } from 'react';
import type { AgentStep, FirewallLogEntry, HostEvent, LogResponse, RunRequest, StateResponse, VerifierLogEntry } from '../shared/api.ts';
import type { InboxMessage } from '../demo/inbox.ts';
import { Api, loadToken } from './api.ts';
import { AuditTab } from './components/AuditTab.tsx';
import { DemoTab } from './components/DemoTab.tsx';
import { PolicyTab, type RecordView } from './components/PolicyTab.tsx';
import { Badge, Notice } from './components/ui.tsx';
import { VerifierTab } from './components/VerifierTab.tsx';
import { shortHex } from './labels.ts';
import { listPolicies, type StoredPolicy } from './storage.ts';

export interface RunView {
  readonly runId: string;
  readonly options: Required<RunRequest>;
  readonly steps: AgentStep[];
  readonly firewall: Record<string, FirewallLogEntry>;
  readonly verifier: Record<string, VerifierLogEntry>;
  finished?: { exitCode: number | null; error?: string };
}

const TABS = [
  { id: 'policy', label: 'Policy & passkey' },
  { id: 'demo', label: 'Live demo' },
  { id: 'audit', label: 'Audit log' },
  { id: 'verifier', label: 'Verifier view' },
] as const;
type TabId = (typeof TABS)[number]['id'];

export function App() {
  const token = useMemo(() => loadToken(), []);
  const api = useMemo(() => (token ? new Api(token) : undefined), [token]);
  const [tab, setTab] = useState<TabId>('policy');
  const [state, setState] = useState<StateResponse>();
  const [policies, setPolicies] = useState<StoredPolicy[]>([]);
  const [records, setRecords] = useState<Record<string, RecordView>>({});
  const [run, setRun] = useState<RunView>();
  const [log, setLog] = useState<LogResponse>();
  const [inbox, setInbox] = useState<InboxMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string>();

  const refresh = useCallback(async () => {
    if (!api) return;
    try {
      const [s, ps] = await Promise.all([api.get<StateResponse>('/api/state'), listPolicies()]);
      setState(s);
      setPolicies(ps);
      const rs = ps.length ? await api.post<RecordView[]>('/api/policies/records', { commitments: ps.map((p) => p.policyCommitment) }) : [];
      setRecords(Object.fromEntries(rs.map((r) => [r.policyCommitment, r])));
      setError(undefined);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [api]);

  const refreshLog = useCallback(async () => {
    if (api) setLog(await api.get<LogResponse>('/api/log'));
  }, [api]);

  useEffect(() => {
    void refresh();
    void refreshLog();
    if (api) void api.get<InboxMessage[]>('/api/inbox').then(setInbox);
  }, [api, refresh, refreshLog]);

  useEffect(() => {
    if (!api) return;
    const ctl = new AbortController();
    const onEvent = (e: HostEvent) => {
      if (e.type === 'run_started') setRun({ runId: e.runId, options: e.options, steps: [], firewall: {}, verifier: {} });
      else if (e.type === 'agent') setRun((r) => (r && r.runId === e.runId ? { ...r, steps: [...r.steps, e.step] } : r));
      else if (e.type === 'firewall' && e.entry.callId)
        setRun((r) => (r && r.runId === e.runId ? { ...r, firewall: { ...r.firewall, [e.entry.callId!]: e.entry } } : r));
      else if (e.type === 'verifier' && e.entry.callId)
        setRun((r) => (r && r.runId === e.runId ? { ...r, verifier: { ...r.verifier, [e.entry.callId!]: e.entry } } : r));
      else if (e.type === 'run_finished') {
        setRun((r) => (r && r.runId === e.runId ? { ...r, finished: { exitCode: e.exitCode, ...(e.error ? { error: e.error } : {}) } } : r));
        void refresh();
        void refreshLog();
      } else void refresh();
    };
    void api.streamEvents(onEvent, setConnected, ctl.signal);
    return () => ctl.abort();
  }, [api, refresh, refreshLog]);

  if (!api) {
    return (
      <main className="mx-auto max-w-xl px-4 py-24">
        <Notice tone="warn">
          <p className="font-semibold">Open the dashboard from the link printed in the terminal.</p>
          <p className="mt-1">It carries a session token in the part after <span className="mono">#</span>, which only your browser sees.</p>
        </Notice>
      </main>
    );
  }

  const armed = state?.firewall.armed ? state.firewall.policyCommitment : undefined;
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="flex items-center gap-2.5">
            <svg viewBox="0 0 24 24" className="size-7 text-emerald-600" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
            <div>
              <h1 className="text-base leading-tight font-semibold">Intent Firewall</h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">Zero-knowledge proof of intent for AI agents</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs" data-testid="status-bar">
            <Badge tone={state?.passkey.enrolled ? 'good' : 'warn'}>{state?.passkey.enrolled ? 'Passkey enrolled' : 'No passkey'}</Badge>
            <Badge tone={armed ? 'good' : 'neutral'} title={armed}>
              {armed ? `Firewall armed · ${shortHex(armed)}` : 'Firewall not armed'}
            </Badge>
            <Badge tone={connected ? 'info' : 'bad'}>{connected ? 'Live' : 'Disconnected'}</Badge>
          </div>
        </div>
        <nav className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-4" aria-label="Sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => {
                setTab(t.id);
                if (t.id === 'audit' || t.id === 'verifier') void refreshLog();
              }}
              className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap ${
                tab === t.id ? 'border-slate-900 text-slate-900 dark:border-white dark:text-white' : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
              }`}
              aria-current={tab === t.id ? 'page' : undefined}
              data-testid={`tab-${t.id}`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        {error && (
          <div className="mb-4">
            <Notice tone="bad">{error}</Notice>
          </div>
        )}
        {tab === 'policy' && <PolicyTab api={api} state={state} policies={policies} records={records} onChange={refresh} onGoToDemo={() => setTab('demo')} />}
        {tab === 'demo' && <DemoTab api={api} state={state} policies={policies} records={records} inbox={inbox} run={run} />}
        {tab === 'audit' && <AuditTab log={log} policies={policies} onRefresh={refreshLog} />}
        {tab === 'verifier' && <VerifierTab log={log} state={state} policies={policies} records={records} />}
      </main>
    </div>
  );
}
