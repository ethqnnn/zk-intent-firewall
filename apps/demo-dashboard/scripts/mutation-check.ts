/**
 * Mutation check of this app's security checks. Each mutant removes or weakens one check in the
 * source, the tests that should notice are run, and the source is restored. A mutant the tests do
 * not kill is a check nothing would miss: the script prints a table and exits non-zero.
 *
 *   node scripts/mutation-check.ts                 all mutants
 *   node scripts/mutation-check.ts R4 H1           only these
 *   node scripts/mutation-check.ts --out=FILE.md   also write the table to FILE.md
 *
 * Only apps/demo-dashboard is mutated. packages/mcp-firewall and packages/zk-circuit have their own
 * suites and are not touched.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const APP_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

interface Mutant {
  readonly id: string;
  /** The check, as it would be described in a review. */
  readonly check: string;
  readonly file: string;
  /** Each `find` must occur exactly once in the file. */
  readonly edits: readonly { readonly find: string; readonly replace: string }[];
  readonly tests: readonly string[];
}

const REGISTRY = 'src/server/verifier/passkey-registry.ts';
const T_REGISTRY = ['test/passkey-registry.test.ts'];

const MUTANTS: readonly Mutant[] = [
  // -- Passkey approval, verifier side ------------------------------------------------------------
  {
    id: 'R1',
    check: 'Approval nonce is single use',
    file: REGISTRY,
    edits: [{ find: '    this.#nonces.delete(request.nonce);\n', replace: '' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R2',
    check: 'Approval nonce expires',
    file: REGISTRY,
    edits: [{ find: "if (issued.expiresAt < this.#o.clock()) return reject('nonce_expired');", replace: '' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R3',
    check: 'Nonce is bound to the action and commitment it was issued for',
    file: REGISTRY,
    edits: [{ find: "if (issued.action !== action || issued.commitment !== commitmentHex) return reject('nonce_mismatch');", replace: '' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R4',
    check: 'Assertion comes from the enrolled credential',
    file: REGISTRY,
    edits: [{ find: "if (response.id !== owner.id) return reject('unknown_credential');", replace: '' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R5',
    check: 'Challenge is rebuilt from verifier state, not taken from the client',
    file: REGISTRY,
    edits: [{ find: 'const expectedChallenge = await statementChallenge(statement);', replace: 'const expectedChallenge = ((c: string) => c.length > 0) as never;' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R6',
    check: 'Signed statement covers every pinned VK hash',
    file: REGISTRY,
    edits: [
      {
        find: 'vkHashes: this.vkHashes(), nonce: request.nonce };',
        replace: "vkHashes: { 'noir-recursive': PINNED_VERIFICATION_KEYS['noir-recursive'].bbHash }, nonce: request.nonce };",
      },
    ],
    tests: T_REGISTRY,
  },
  {
    id: 'R7',
    check: 'Signed statement carries the protocol label',
    file: REGISTRY,
    edits: [{ find: 'const statement: ApprovalStatement = { label: APPROVAL_LABEL, action, policyCommitment', replace: "const statement: ApprovalStatement = { label: 'zkif.webauthn.v1', action, policyCommitment" }],
    tests: T_REGISTRY,
  },
  {
    id: 'R8',
    check: 'Signature verification result is enforced',
    file: REGISTRY,
    edits: [{ find: 'if (verification.verified !== true || verification.authenticationInfo.userVerified !== true)', replace: 'if (false)' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R9',
    check: 'User verification is required (both layers)',
    file: REGISTRY,
    edits: [
      { find: '        credential: owner,\n        requireUserVerification: true,', replace: '        credential: owner,\n        requireUserVerification: false,' },
      { find: ' || verification.authenticationInfo.userVerified !== true)', replace: ')' },
    ],
    tests: T_REGISTRY,
  },
  {
    id: 'R10',
    check: 'Assertion origin is checked',
    file: REGISTRY,
    edits: [{ find: '        expectedOrigin: [...this.#o.expectedOrigins],\n        expectedRPID: this.#o.rpId,\n        credential: owner,', replace: '        expectedOrigin: ((o: string) => o.length > 0) as never,\n        expectedRPID: this.#o.rpId,\n        credential: owner,' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R11',
    check: 'Assertion RP ID is checked',
    file: REGISTRY,
    edits: [{ find: '        expectedRPID: this.#o.rpId,\n        credential: owner,', replace: '        expectedRPID: undefined as never,\n        credential: owner,' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R12',
    check: 'Signature counter is tracked (cloned authenticator)',
    file: REGISTRY,
    edits: [{ find: '    this.#owner = { ...owner, counter: verification.authenticationInfo.newCounter };\n', replace: '' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R13',
    check: 'A revoked commitment cannot be registered again (both layers)',
    file: REGISTRY,
    edits: [
      { find: "    if (this.#inner.status(v.commitment) === 'revoked') return reject('commitment_revoked');\n", replace: '' },
      { find: "if (action === 'register' && this.#inner.status(parseField(commitment)) === 'revoked') {", replace: 'if (false) {' },
    ],
    tests: [...T_REGISTRY, 'test/revocation.test.ts'],
  },
  {
    id: 'R14',
    check: 'Enrolment is trust-on-first-use only (both layers)',
    file: REGISTRY,
    edits: [
      { find: "    if (this.#owner) return { ok: false, reason: 'owner_already_enrolled' };\n", replace: '' },
      { find: "    if (this.#owner) throw new Error('a policy owner passkey is already enrolled');\n", replace: '' },
    ],
    tests: T_REGISTRY,
  },
  {
    id: 'R15',
    check: 'Enrolment challenge expires',
    file: REGISTRY,
    edits: [{ find: "if (pending.expiresAt < this.#o.clock()) return { ok: false, reason: 'enrollment_expired' };", replace: '' }],
    tests: T_REGISTRY,
  },
  {
    id: 'R16',
    check: 'Revocation reaches the registry',
    file: REGISTRY,
    edits: [{ find: "    this.#inner.revoke(v.commitment, 'revoked by policy owner passkey');\n", replace: '' }],
    tests: ['test/revocation.test.ts'],
  },

  // -- Approval statement, shared by browser and verifier -------------------------------------------
  {
    id: 'S1',
    check: 'Statement text includes the nonce',
    file: 'src/shared/approval.ts',
    edits: [{ find: '    `nonce: ${s.nonce}`,\n', replace: '' }],
    tests: ['test/approval.test.ts', ...T_REGISTRY],
  },
  {
    id: 'S2',
    check: 'Statement text includes the VK hashes',
    file: 'src/shared/approval.ts',
    edits: [{ find: '    ...targets.map((t) => `vk_hash.${t}: ${s.vkHashes[t]}`),\n', replace: '' }],
    tests: ['test/approval.test.ts', ...T_REGISTRY],
  },
  {
    id: 'S3',
    check: 'Statement text includes the action',
    file: 'src/shared/approval.ts',
    edits: [{ find: '    `action: ${s.action}`,\n', replace: '' }],
    tests: ['test/approval.test.ts', ...T_REGISTRY],
  },

  // -- Browser: refuse to sign a statement other than the one requested ----------------------------
  ...(
    [
      ['B1', 'protocol label', "if (s.label !== APPROVAL_LABEL) problems.push('protocol label');"],
      ['B2', 'action', "if (s.action !== action) problems.push('action');"],
      ['B3', 'policy commitment', "if (s.policyCommitment !== policyCommitment) problems.push('policy commitment');"],
      ['B4', 'pinned VK hashes', "problems.push('verification keys');"],
      ['B5', 'displayed text', "if (text !== ch.statementText) problems.push('statement text');"],
      ['B6', 'challenge', "if ((await statementChallenge(s)) !== ch.challenge) problems.push('challenge');"],
    ] as const
  ).map(([id, what, find]): Mutant => ({
    id,
    check: `Browser refuses to sign: ${what} mismatch`,
    file: 'src/web/passkey.ts',
    edits: [{ find, replace: id === 'B4' ? 'void 0;' : '' }],
    tests: ['test/browser-statement.test.ts'],
  })),

  // -- Tool server --------------------------------------------------------------------------------
  {
    id: 'T1',
    check: 'send_payment executes only with a verified proof',
    file: 'src/server/verifier/treasury.ts',
    edits: [
      {
        find: '        const result = await guarded(args, extra);',
        replace:
          "        const result = envelope ? await guarded(args, extra) : (this.ledger.push({ recipient: canonicalAccount(args.recipient), amount: String(args.amount), at: '0', reference: 'tx-unproven' }), text('Payment sent.'));",
      },
    ],
    tests: ['test/demo.test.ts'],
  },
  {
    id: 'T2',
    check: 'send_payment refuses arguments the proof does not bind',
    file: 'src/server/tools.ts',
    edits: [{ find: '      if (!SEND_PAYMENT_ARGS.has(k)) throw', replace: '      if (false) throw' }],
    tests: ['test/tools.test.ts'],
  },

  // -- Firewall host --------------------------------------------------------------------------------
  {
    id: 'F1',
    check: 'Firewall consults the registry before proving',
    file: 'src/server/host/firewall-host.ts',
    edits: [{ find: '...(session.checkRegistry === false ? {} : { registry: o.registry }),', replace: '' }],
    tests: ['test/revocation.test.ts'],
  },
  {
    id: 'F2',
    check: 'Policy salt carries at least 128 bits',
    file: 'src/server/host/host.ts',
    edits: [{ find: "if (salt < 1n << 128n) throw new Error('salt must carry at least 128 bits');", replace: '' }],
    tests: ['test/isolation.test.ts'],
  },

  // -- Dashboard API --------------------------------------------------------------------------------
  {
    id: 'H1',
    check: 'API requires the session token',
    file: 'src/server/host/host.ts',
    edits: [{ find: 'return a.length === b.length && timingSafeEqual(a, b);', replace: 'return true;' }],
    tests: ['test/isolation.test.ts'],
  },
  {
    id: 'H2',
    check: 'POST requires same origin',
    file: 'src/server/host/http.ts',
    edits: [{ find: "if (req.headers.origin !== host.origin) return json(res, 403, { error: 'cross-origin request refused' });", replace: '' }],
    tests: ['test/isolation.test.ts'],
  },
  {
    id: 'H3',
    check: 'POST requires a JSON content type',
    file: 'src/server/host/http.ts',
    edits: [{ find: "return json(res, 415, { error: 'JSON body required' });", replace: 'void 0;' }],
    tests: ['test/isolation.test.ts'],
  },

  // -- Agent sandbox ------------------------------------------------------------------------------
  {
    id: 'X1',
    check: 'Agent runs under the permission model',
    file: 'src/server/host/sandbox.ts',
    edits: [{ find: "return ['--permission', ...[entry, ...SANDBOX_READ_PATHS]", replace: 'return [...[entry, ...SANDBOX_READ_PATHS]' }],
    tests: ['test/isolation.test.ts'],
  },
  {
    id: 'X2',
    check: 'Agent read access is limited to its own code',
    file: 'src/server/host/sandbox.ts',
    edits: [{ find: "  resolve(REPO_ROOT, 'node_modules'),\n];", replace: '  REPO_ROOT,\n];' }],
    tests: ['test/isolation.test.ts'],
  },
  {
    id: 'X3',
    check: "Agent does not inherit the host's environment",
    file: 'src/server/host/sandbox.ts',
    edits: [{ find: '    env: { ...SANDBOX_ENV },', replace: '    env: { ...process.env, ...SANDBOX_ENV },' }],
    tests: ['test/isolation.test.ts'],
  },
];

// ---------------------------------------------------------------------------------------------

interface Outcome {
  readonly mutant: Mutant;
  readonly killed: boolean;
  readonly killedBy: readonly string[];
  readonly seconds: number;
}

function runTests(files: readonly string[]): { ok: boolean; failed: string[] } {
  const dir = mkdtempSync(join(tmpdir(), 'zkif-mutation-'));
  const report = join(dir, 'report.json');
  try {
    const r = spawnSync(join(APP_ROOT, 'node_modules/.bin/vitest'), ['run', ...files, '--reporter=json', `--outputFile=${report}`], { cwd: APP_ROOT, encoding: 'utf8', timeout: 600_000 });
    let failed: string[] = [];
    try {
      const json = JSON.parse(readFileSync(report, 'utf8')) as { testResults: { name: string; status: string; assertionResults: { fullName: string; status: string }[] }[] };
      failed = json.testResults.flatMap((f) => [
        ...f.assertionResults.filter((a) => a.status === 'failed').map((a) => a.fullName),
        // A suite that fails to load or set up has no failed assertions of its own.
        ...(f.status === 'failed' && !f.assertionResults.some((a) => a.status === 'failed') ? [`${f.name.replace(APP_ROOT + '/', '')} (suite failed)`] : []),
      ]);
    } catch {
      failed = ['(no test report: the run crashed)'];
    }
    return { ok: r.status === 0, failed };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function count(haystack: string, needle: string): number {
  let n = 0;
  for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + needle.length)) n++;
  return n;
}

const args = process.argv.slice(2);
const out = args.find((a) => a.startsWith('--out='))?.slice(6);
const only = args.filter((a) => !a.startsWith('--'));
const selected = only.length > 0 ? MUTANTS.filter((m) => only.includes(m.id)) : MUTANTS;
if (selected.length === 0) throw new Error(`no mutant matches ${only.join(' ')}`);

// Every mutation must apply exactly once to today's source, or the check proves nothing.
for (const m of selected) {
  const src = readFileSync(resolve(APP_ROOT, m.file), 'utf8');
  for (const e of m.edits) {
    const n = count(src, e.find);
    if (n !== 1) throw new Error(`${m.id}: expected exactly one occurrence in ${m.file}, found ${n}:\n${e.find}`);
  }
}

// Restore on interrupt.
const originals = new Map<string, string>();
const restoreAll = () => {
  for (const [file, src] of originals) writeFileSync(file, src);
};
for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    restoreAll();
    process.exit(130);
  });
}

const allTests = [...new Set(selected.flatMap((m) => m.tests))];
console.log(`Baseline: ${allTests.join(', ')}`);
const baseline = runTests(allTests);
if (!baseline.ok) {
  console.error(`The unmutated tests fail; fix them first:\n  ${baseline.failed.join('\n  ')}`);
  process.exit(2);
}

const outcomes: Outcome[] = [];
for (const m of selected) {
  const path = resolve(APP_ROOT, m.file);
  const original = readFileSync(path, 'utf8');
  originals.set(path, original);
  let mutated = original;
  for (const e of m.edits) mutated = mutated.replace(e.find, () => e.replace);
  const started = performance.now();
  writeFileSync(path, mutated);
  let r: ReturnType<typeof runTests>;
  try {
    r = runTests(m.tests);
  } finally {
    writeFileSync(path, original);
    originals.delete(path);
  }
  const o = { mutant: m, killed: !r.ok, killedBy: r.failed, seconds: (performance.now() - started) / 1000 };
  outcomes.push(o);
  console.log(`${m.id.padEnd(4)} ${o.killed ? 'killed  ' : 'SURVIVED'} ${m.check} (${o.seconds.toFixed(1)} s, ${r.failed.length} failing)`);
}

const cell = (s: string) => s.replace(/\|/g, '\\|');
const table = [
  '| # | Check removed or weakened | File | Result | Failing tests (first) |',
  '|---|---|---|---|---|',
  ...outcomes.map(
    (o) =>
      `| ${o.mutant.id} | ${cell(o.mutant.check)} | \`${o.mutant.file.replace('src/', '')}\` | ${o.killed ? 'killed' : '**survived**'} | ${o.killed ? `${o.killedBy.length}: ${cell(o.killedBy[0] ?? '')}` : ''} |`,
  ),
].join('\n');
const survived = outcomes.filter((o) => !o.killed);
const summary = `${outcomes.length - survived.length} of ${outcomes.length} mutants killed${survived.length ? `; survived: ${survived.map((o) => o.mutant.id).join(', ')}` : ''}.`;
console.log(`\n${table}\n\n${summary}`);
if (out) writeFileSync(resolve(process.cwd(), out), `${table}\n\n${summary}\n`);
process.exit(survived.length === 0 ? 0 : 1);
