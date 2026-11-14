# Contributing

Thank you for your interest. This is alpha security software, so changes are held to one rule:
**every security check has a test that fails when the check is removed.** The mutation checks
below enforce that.

Please report vulnerabilities privately ([SECURITY.md](SECURITY.md)), not in an issue or a pull
request.

## Setup

| Tool | Version | Needed for |
|---|---|---|
| Node.js | 26 (`.nvmrc`) | everything |
| pnpm | 12.18.0 (`packageManager`; `npm install -g pnpm@12`) | everything |
| nargo | 1.0.0 (`noirup -v 1.0.0`) | the circuit's tests, build and mutation check |
| bb | 5.3.0 (`bbup -v 5.3.0`) | native prove/verify checks only; must match `@aztec/bb.js` 5.3.0 |
| Playwright Chromium | as pinned by `@playwright/test` | the end-to-end test only |

```sh
pnpm install
pnpm --filter @zk-intent-firewall/demo-dashboard exec playwright install chromium   # e2e only
```

The first proof downloads Barretenberg's reference string and caches it.

## Run all the tests

From the repository root:

```sh
pnpm test                 # circuit (nargo test, 152 tests), firewall and dashboard vitest suites
pnpm firewall:typecheck   # TypeScript, firewall sources and tests
pnpm dashboard:typecheck  # TypeScript, dashboard server and browser code
pnpm dashboard:test:e2e   # builds, then Playwright drives the dashboard with a virtual authenticator
pnpm circuit:verify       # format, security-path, tests, dependency pin, fixtures, execute
```

`pnpm test` takes under a minute. The dashboard suites start real processes and make real
proofs.

Narrower runs:

| Command | What it runs |
|---|---|
| `pnpm circuit:test` | `nargo test --workspace --deny-warnings` |
| `pnpm firewall:test` | `packages/mcp-firewall` vitest: fixture vectors, prover, end-to-end firewall, prompt injection |
| `pnpm dashboard:test` | `apps/demo-dashboard` vitest: passkey registry, approval, revocation, isolation, demo |
| `pnpm firewall:check:bbjs` | bb.js prove/verify round trip on both targets, key hashes, tamper rejection; cross-checks with native `bb` when it is on `PATH` |
| `pnpm --filter @zk-intent-firewall/zk-circuit run prove` | Native `bb` prove and verify round trip, with tampering checks and timings |

## Run the mutation checks

Each one changes the source one check at a time, runs the tests that should notice, and restores
the file afterwards, including on Ctrl-C. A mutant that survives is a missing test, and the
script exits with an error. Commit or stash your work first anyway.

```sh
pnpm dashboard:mutation                                    # about 90 s
pnpm --filter @zk-intent-firewall/zk-circuit run mutation  # about 2.5 minutes
```

- **Dashboard** (`apps/demo-dashboard/scripts/mutation-check.ts`): weakens each check of the
  passkey registry, approval statement, browser signing guard, tool server, firewall host, API
  guards and agent sandbox, the way a real bug would. It refuses to run if a mutation no longer
  applies exactly once, or if the unmutated tests fail. The current table is in the
  [dashboard README](apps/demo-dashboard/README.md#mutation-check).
- **Circuit** (`packages/zk-circuit/scripts/mutation-check.sh`): removes every assertion of the
  circuit in turn, then applies a list of small semantic changes to the security path. It writes
  its report to `packages/zk-circuit/target/mutation-report.md`.

If you add a security check, add a test that fails without it and, in the dashboard, a mutant in
`scripts/mutation-check.ts` that removes it.

## Changing the circuit

The circuit's contract is [`docs/circuit-spec.md`](docs/circuit-spec.md). A change to the
statement, the inputs or the hashing changes the verification keys, so:

1. Update the spec first.
2. `pnpm --filter @zk-intent-firewall/zk-circuit run fixtures:generate` regenerates the fixtures,
   and `pnpm --filter @zk-intent-firewall/zk-circuit run build` compiles the circuit.
3. `node packages/mcp-firewall/scripts/sync-circuit.mjs --write` copies the compiled circuit into
   `packages/mcp-firewall` and rewrites its pinned keys.
4. Update the key hashes pinned in `apps/demo-dashboard/src/shared/approval.ts`. A test checks
   that all three copies agree.

The security path (`crates/policy_primitives` and `crates/proof_of_intent/src/main.nr`) may not
contain `unconstrained` functions or `unsafe` blocks; `check:security-path` enforces it.

## Pull requests

- Keep each pull request to one change, with tests.
- Run `pnpm test` and both typechecks before you open it, and the mutation check of whatever you
  touched.
- Pin new dependencies to an exact version and say why they are needed.

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
