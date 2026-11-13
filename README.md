# zk-intent-firewall

A zero-knowledge proof-of-intent firewall for AI agents that use the Model Context Protocol (MCP).

An agent cannot tell a human's instruction from text injected into its inputs, and API keys are
all-or-nothing. Here a human approves a **policy** once (a per-action spending limit, a recipient
allowlist, the allowed action scopes and an expiry) and binds it to a public commitment. Before a
sensitive tool call executes, a zero-knowledge proof shows that the call obeys the policy. The
tool server learns that the call is allowed and nothing else about the policy.

## Status

| Phase | Part | State |
|---|---|---|
| 1 | Noir circuit, spec, fixtures | Done. Not audited. |
| 2 | TypeScript MCP middleware and verifier SDK | Placeholder |
| 3 | Demo dashboard | Placeholder |

The licence has not been decided yet, so there is no `LICENSE` file.

## Layout

```
docs/circuit-spec.md            the contract: statement, inputs in order, hashes, threat model
packages/zk-circuit/            Noir workspace
  crates/policy_primitives/     library: hashes, Merkle root, commitment, binding (security path)
  crates/proof_of_intent/       the circuit and its tests (security path: src/main.nr)
  crates/testkit/               off-circuit reference tree builder and the canonical scenario
  crates/fixture_gen/           prints the fixtures
  fixtures/                     Prover.toml, vectors.json, vk_hashes.txt
  scripts/                      fixtures, dependency pin, security-path, prove/verify, mutation
packages/mcp-firewall/          Phase 2 placeholder
apps/demo-dashboard/            Phase 3 placeholder
```

## Prerequisites

Exact versions this was built and tested with:

| Tool | Version | Install |
|---|---|---|
| nargo (Noir) | 1.0.0 | `noirup -v 1.0.0` |
| bb (Barretenberg) | 6.0.0 | `bbup`, which pairs it with nargo 1.0.0. Only needed for real proofs |
| Node.js | 26.13.1 | `.nvmrc` holds the major version |
| pnpm | 12.18.0 | pinned by `packageManager` |
| `noir-lang/poseidon` | tag `v0.4.0`, commit `e105cdd5c79c222860d53c5dfdb8fa8012b291c0` | fetched by nargo on first use |

The project has no JavaScript dependencies. `pnpm-lock.yaml` pins only pnpm itself.

## Commands

From the repository root:

| Command | What it does |
|---|---|
| `pnpm test` | `nargo test` on the whole workspace: 152 tests |
| `pnpm build` | Compile the circuit to `packages/zk-circuit/target/proof_of_intent.json` |
| `pnpm circuit:test` | The same tests, through the circuit package |
| `pnpm circuit:info` | ACIR opcode count |
| `pnpm circuit:execute` | Run the circuit on `fixtures/Prover.toml` |
| `pnpm circuit:fmt:check` | `nargo fmt --check` |
| `pnpm circuit:verify` | Format check, security-path check, tests, dependency pin, fixture check, execute |

In `packages/zk-circuit`:

| Command | What it does |
|---|---|
| `pnpm run prove` | Real prove and verify round trip with `bb`, with tampering checks and timings |
| `pnpm run mutation` | Mutation check: removes every assertion in turn, about 2.5 minutes |
| `pnpm run fixtures:generate` | Regenerate the fixtures from the Noir code |
| `pnpm run gates` | Gate count from `bb` |

## The circuit at a glance

Public inputs, in order: `policy_commitment`, `current_timestamp`, `action_binding`.

| Measure | Value |
|---|---|
| ACIR opcodes (`nargo info`) | 562 |
| Gates (`bb gates`) | 5,237 |
| Poseidon2 permutations | 26 |
| Prove, `bb` 6.0.0, 12 threads | about 110 to 135 ms |
| Verify | about 7 to 10 ms |
| Proof size | 7,616 bytes (`evm` target) or 14,656 bytes (`noir-recursive` target) |

Read [`docs/circuit-spec.md`](docs/circuit-spec.md) before building on the circuit. Section 9
lists what the circuit does not do: it enforces a per-action limit only, and revocation, replay
tracking and the passkey signature are the verifier's job.
