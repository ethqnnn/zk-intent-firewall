import { type FormEvent, useState } from 'react';
import type { ChallengeResponse, PreparePolicyResponse, StateResponse } from '../../shared/api.ts';
import type { ApprovalAction } from '../../shared/approval.ts';
import { canonicalAccount, DEMO_POLICY_PRESET, SCOPE_DESCRIPTIONS, SCOPES, type ScopeName, USDC_DECIMALS } from '../../shared/demo-config.ts';
import { toBaseUnits } from '../../shared/units.ts';
import type { Api } from '../api.ts';
import { shortHex } from '../labels.ts';
import { enrolPasskey, requestStatement, signAndSubmit } from '../passkey.ts';
import { deletePolicy, savePolicy, type StoredPayee, type StoredPolicy } from '../storage.ts';
import { Badge, Button, Card, Field, inputClass, Mono, Notice, Spinner } from './ui.tsx';

export interface RecordView {
  readonly policyCommitment: string;
  readonly status: 'active' | 'revoked' | 'unknown';
  readonly registeredAt?: string;
  readonly revokedAt?: string;
}

interface Props {
  api: Api;
  state: StateResponse | undefined;
  policies: StoredPolicy[];
  records: Record<string, RecordView>;
  onChange: () => Promise<void>;
  onGoToDemo: () => void;
}

export function PolicyTab({ api, state, policies, records, onChange, onGoToDemo }: Props) {
  const [approval, setApproval] = useState<{ policy: StoredPolicy; challenge: ChallengeResponse }>();
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();

  const run = async (label: string, f: () => Promise<void>) => {
    setBusy(label);
    setError(undefined);
    try {
      await f();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(undefined);
      await onChange();
    }
  };

  const startApproval = (policy: StoredPolicy, action: ApprovalAction) =>
    run(`${action}:${policy.policyCommitment}`, async () => setApproval({ policy, challenge: await requestStatement(api, action, policy.policyCommitment) }));

  const armed = state?.firewall.armed ? state.firewall.policyCommitment : undefined;

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
      <div className="space-y-6">
        <Card title="1. Your passkey" subtitle="The verifier activates a policy only when this passkey signs it.">
          {state?.passkey.enrolled ? (
            <div className="space-y-2 text-sm">
              <Badge tone="good">Enrolled with the treasury verifier</Badge>
              <p className="text-slate-500 dark:text-slate-400">
                Credential <Mono>{shortHex(state.passkey.credentialId)}</Mono>. Enrolment is closed now that an owner exists (trust on first use).
              </p>
            </div>
          ) : (
            <div className="space-y-3 text-sm">
              <p>Create a passkey on this device (Face ID, Touch ID, Windows Hello or a security key). Its public key is enrolled with the treasury verifier.</p>
              <Button testId="enrol-passkey" disabled={!!busy} onClick={() => run('enrol', async () => void (await enrolPasskey(api)))}>
                {busy === 'enrol' && <Spinner />} Create passkey
              </Button>
            </div>
          )}
        </Card>
        <PolicyEditor api={api} disabled={!!busy} onCreated={onChange} />
      </div>

      <div className="space-y-6">
        {error && <Notice tone="bad">{error}</Notice>}
        <Card title="3. Policies" subtitle="Stored only in this browser. The verifier sees each one as a commitment, nothing more.">
          {policies.length === 0 ? (
            <p className="text-sm text-slate-500 dark:text-slate-400">No policies yet. Create one on the left.</p>
          ) : (
            <ul className="space-y-4" data-testid="policy-list">
              {policies.map((p) => {
                const status = records[p.policyCommitment]?.status ?? 'unknown';
                const isArmed = armed === p.policyCommitment;
                return (
                  <li key={p.policyCommitment} className="rounded-lg border border-slate-200 p-4 dark:border-slate-800" data-testid="policy-item">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 className="font-medium">{p.name}</h3>
                      <div className="flex gap-1.5">
                        <Badge tone={status === 'active' ? 'good' : status === 'revoked' ? 'bad' : 'neutral'}>
                          <span data-testid="policy-status">{status === 'unknown' ? 'not approved' : status}</span>
                        </Badge>
                        {isArmed && <Badge tone="info">armed</Badge>}
                      </div>
                    </div>
                    <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                      <dt className="text-slate-500">Per payment</dt>
                      <dd>at most {p.definition.maxAmountUsdc} USDC</dd>
                      <dt className="text-slate-500">Payees</dt>
                      <dd>{p.definition.payees.map((x) => x.label).join(', ')}</dd>
                      <dt className="text-slate-500">Allowed</dt>
                      <dd>{p.definition.scopes.join(', ')}</dd>
                      <dt className="text-slate-500">Expires</dt>
                      <dd>{new Date(Number(p.definition.expiry) * 1000).toLocaleString()}</dd>
                      <dt className="text-slate-500">Commitment</dt>
                      <dd>
                        <Mono title={p.policyCommitment}>{shortHex(p.policyCommitment)}</Mono>
                      </dd>
                    </dl>
                    <div className="mt-4 flex flex-wrap gap-2">
                      {status === 'unknown' && (
                        <Button testId="approve-policy" disabled={!!busy || !state?.passkey.enrolled} onClick={() => void startApproval(p, 'register')}>
                          Approve with passkey
                        </Button>
                      )}
                      {status !== 'unknown' && !isArmed && (
                        <Button
                          testId="arm-policy"
                          variant="secondary"
                          disabled={!!busy}
                          onClick={() => run('arm', async () => void (await api.post('/api/firewall/arm', { opening: p.opening })))}
                        >
                          Arm firewall
                        </Button>
                      )}
                      {isArmed && (
                        <Button variant="secondary" onClick={onGoToDemo}>
                          Go to live demo →
                        </Button>
                      )}
                      {status === 'active' && (
                        <Button testId="revoke-policy" variant="danger" disabled={!!busy} onClick={() => void startApproval(p, 'revoke')}>
                          Revoke
                        </Button>
                      )}
                      {status !== 'active' && !isArmed && (
                        <Button variant="secondary" disabled={!!busy} onClick={() => run('delete', () => deletePolicy(p.policyCommitment))}>
                          Delete from this browser
                        </Button>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
        <Notice tone="neutral">
          <p className="font-medium">Where the policy lives</p>
          <p className="mt-1">
            The policy opening (limit, payees, scopes, expiry and the secret salt) is kept in this browser's IndexedDB. It is sent to the local firewall only
            when you arm it, and the firewall keeps it in memory. The agent runs in a sandboxed process that cannot read files or open connections; the
            treasury verifier only ever receives the commitment. This is the Phase 3 demo approach, not custody for real funds.
          </p>
        </Notice>
      </div>

      {approval && (
        <ApprovalDialog
          challenge={approval.challenge}
          policy={approval.policy}
          onCancel={() => setApproval(undefined)}
          onSign={() =>
            run('sign', async () => {
              const r = await signAndSubmit(api, approval.challenge);
              setApproval(undefined);
              if (!r.ok) throw new Error(`The verifier refused the approval: ${r.reason}`);
            })
          }
          busy={busy === 'sign'}
        />
      )}
    </div>
  );
}

function ApprovalDialog({ challenge, policy, onCancel, onSign, busy }: { challenge: ChallengeResponse; policy: StoredPolicy; onCancel: () => void; onSign: () => void; busy: boolean }) {
  const revoke = challenge.statement.action === 'revoke';
  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-slate-950/50 p-4" role="dialog" aria-modal="true" aria-labelledby="approval-title">
      <div className="enter w-full max-w-2xl rounded-xl bg-white shadow-xl dark:bg-slate-900">
        <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-800">
          <h2 id="approval-title" className="text-base font-semibold">
            {revoke ? 'Revoke' : 'Approve'} “{policy.name}”
          </h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Your passkey signs this statement. The dashboard rebuilt it from the commitment it holds and the keys it pins, and it matches the verifier's.
          </p>
        </div>
        <div className="space-y-3 px-5 py-4">
          <pre className="mono rounded-lg bg-slate-50 p-3 leading-relaxed break-all whitespace-pre-wrap dark:bg-slate-950" data-testid="approval-statement">
            {challenge.statementText}
          </pre>
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-600 dark:text-slate-400">
            <li>The label ties the signature to this protocol, and the action to {revoke ? 'revocation' : 'registration'} only.</li>
            <li>The verification key hashes tie it to this exact circuit: it cannot be reused for another one.</li>
            <li>The nonce was issued by the verifier for this request and is accepted once.</li>
            {revoke && <li className="font-medium text-rose-700 dark:text-rose-400">Revocation is final. Proofs under this policy stop working immediately, before its expiry.</li>}
          </ul>
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-3 dark:border-slate-800">
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button testId="sign-approval" variant={revoke ? 'danger' : 'primary'} onClick={onSign} disabled={busy}>
            {busy && <Spinner />} Sign with passkey
          </Button>
        </div>
      </div>
    </div>
  );
}

function PolicyEditor({ api, disabled, onCreated }: { api: Api; disabled: boolean; onCreated: () => Promise<void> }) {
  const defaultExpiry = () => {
    const d = new Date(Date.now() + DEMO_POLICY_PRESET.validForDays * 86_400_000);
    d.setSeconds(0, 0);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  };
  const [name, setName] = useState<string>(DEMO_POLICY_PRESET.name);
  const [max, setMax] = useState<string>(DEMO_POLICY_PRESET.maxAmountUsdc);
  const [payees, setPayees] = useState<StoredPayee[]>(DEMO_POLICY_PRESET.payees.map((p) => ({ ...p })));
  const [scopes, setScopes] = useState<ScopeName[]>([...DEMO_POLICY_PRESET.scopes]);
  const [expiry, setExpiry] = useState(defaultExpiry);
  const [error, setError] = useState<string>();
  const [saving, setSaving] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    setSaving(true);
    try {
      const cleaned = payees.filter((p) => p.label.trim() || p.account.trim()).map((p) => ({ label: p.label.trim() || 'Payee', account: canonicalAccount(p.account) }));
      if (cleaned.length === 0) throw new Error('Add at least one payee.');
      if (scopes.length === 0) throw new Error('Allow at least one action.');
      const maxBase = toBaseUnits(max, USDC_DECIMALS);
      if (maxBase === 0n) throw new Error('The per-payment limit must be above zero.');
      const expirySeconds = Math.floor(new Date(expiry).getTime() / 1000);
      if (!Number.isFinite(expirySeconds) || expirySeconds <= Date.now() / 1000) throw new Error('The expiry must be in the future.');
      const prepared = await api.post<PreparePolicyResponse>('/api/policies/prepare', {
        maxAmount: maxBase.toString(),
        recipients: cleaned.map((p) => p.account),
        scopes,
        expiry: String(expirySeconds),
        salt: randomSalt(),
      });
      await savePolicy({
        policyCommitment: prepared.policyCommitment,
        name: name.trim() || 'Untitled policy',
        createdAt: new Date().toISOString(),
        definition: { maxAmountUsdc: max.trim(), payees: cleaned, scopes, expiry: String(expirySeconds) },
        opening: prepared.opening,
      });
      await onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card title="2. Author a policy" subtitle="What the agent may do without asking you again.">
      <form className="space-y-4" onSubmit={(e) => void submit(e)}>
        <Field label="Name">
          <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
        </Field>
        <Field label="Limit per payment (USDC)" hint="Each single payment must be at or below this. There is no running total (spec L1).">
          <input className={inputClass} value={max} onChange={(e) => setMax(e.target.value)} inputMode="decimal" data-testid="max-amount" />
        </Field>
        <fieldset>
          <legend className="text-sm font-medium">Allowed payees</legend>
          <p className="text-xs text-slate-500 dark:text-slate-400">USDC on Ethereum. Each address is committed exactly; a lookalike address is a different payee.</p>
          <div className="mt-2 space-y-2">
            {payees.map((p, i) => (
              <div key={i} className="grid grid-cols-[minmax(0,0.8fr)_minmax(0,1.4fr)_auto] gap-2">
                <input className={inputClass} placeholder="Label" aria-label={`Payee ${i + 1} label`} value={p.label} onChange={(e) => setPayees(payees.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)))} />
                <input
                  className={`${inputClass} mono`}
                  placeholder="0x… or eip155:1:0x…"
                  aria-label={`Payee ${i + 1} address`}
                  title={p.account}
                  value={p.account}
                  onChange={(e) => setPayees(payees.map((x, j) => (j === i ? { ...x, account: e.target.value } : x)))}
                />
                <button type="button" className="rounded-lg px-2 text-slate-400 hover:text-rose-600" aria-label={`Remove payee ${i + 1}`} onClick={() => setPayees(payees.filter((_, j) => j !== i))}>
                  ✕
                </button>
              </div>
            ))}
          </div>
          <button type="button" className="mt-2 text-sm font-medium text-sky-700 hover:underline dark:text-sky-400" onClick={() => setPayees([...payees, { label: '', account: '' }])}>
            + Add payee
          </button>
        </fieldset>
        <fieldset>
          <legend className="text-sm font-medium">Allowed actions</legend>
          <div className="mt-2 space-y-1.5">
            {(Object.keys(SCOPES) as ScopeName[]).map((s) => (
              <label key={s} className="flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-0.5" checked={scopes.includes(s)} onChange={(e) => setScopes(e.target.checked ? [...scopes, s] : scopes.filter((x) => x !== s))} />
                <span>
                  <span className="mono">{s}</span> <span className="text-slate-500 dark:text-slate-400">{SCOPE_DESCRIPTIONS[s]}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <Field label="Expires">
          <input type="datetime-local" className={inputClass} value={expiry} onChange={(e) => setExpiry(e.target.value)} />
        </Field>
        {error && <Notice tone="bad">{error}</Notice>}
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-slate-500 dark:text-slate-400">A fresh random salt is drawn in this browser for every policy.</p>
          <Button type="submit" testId="create-policy" disabled={disabled || saving}>
            {saving && <Spinner />} Create policy
          </Button>
        </div>
      </form>
    </Card>
  );
}

/** A 248-bit salt from the browser's CSPRNG with at least 128 bits set above zero. */
function randomSalt(): string {
  for (;;) {
    const b = crypto.getRandomValues(new Uint8Array(31));
    const hex = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    if (BigInt('0x' + hex) >= 1n << 128n) return '0x' + hex;
  }
}
