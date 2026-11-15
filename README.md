# zk-intent-firewall

![The agent pays a lookalike wallet after a prompt injection; the firewall blocks it, and the run ends with 2 paid and 2 blocked](docs/demo.gif)

Human-approved, third-party-verifiable AI agent payments with a hidden policy, using Noir
zero-knowledge proofs.

**[▶ Watch the demo](https://youtu.be/0l9pcMcDJLk)**

> [!WARNING]
> **Alpha. Not externally audited. Do not use with real funds.**
> The circuit, the TypeScript SDK, the passkey registry and the Poseidon2 library it depends on
> (`noir-lang/poseidon`, which calls itself experimental) have had no external audit. State is
> held in memory, and the policy is stored unencrypted in the browser. See
> [Known limits](#known-limits).

## What it does

An AI agent cannot tell its owner's instructions from text an attacker slipped into an email, an
invoice or a tool description. Giving it a payment API key means trusting it with everything the
key can do.

Here a human approves a **policy** once, with a passkey: a per-payment limit, an allowlist of
recipients, the allowed action scopes and an expiry. Only a salted commitment to the policy is
published. Before a payment tool executes, the firewall must produce a zero-knowledge proof that
this exact call obeys the policy. The tool server verifies the proof before it pays. It learns
that the call is allowed and nothing else: not the limit, not the other payees, not the expiry.
Anyone holding the commitment and the verification key, such as an auditor, can check the same
proof later.

```
 agent ──MCP──▶ firewall (prover) ────────── MCP + proof ──────────▶ tool server (verifier)
                holds the policy, proves                              registry of approved commitments,
                each call or blocks it                                verifies before it executes
```

The firewall does not try to detect prompt injection. It makes an injected payment fail when the
payment is outside what the human approved. Inside the policy, the agent is still trusted.

## Threat model

Each row names the test that demonstrates it. Paths are in the key below the table.

| Threat | What happens | Status |
|---|---|---|
| **Indirect prompt injection** | The agent reads attacker-written text and tries to pay the attacker. The firewall blocks any call outside the policy, and the tool server never sees it. An injected payment that stays inside the policy (an allowlisted payee, under the limit) still goes through. Tests: `demo` › "the redirect is blocked for the recipient, the inflation for the amount, and neither is forwarded"; `prompt-injection` › "redirect to an attacker account: the agent complies, the firewall blocks". | Partial |
| **MCP tool poisoning** (instructions hidden in a tool description) | The proxy forwards the upstream tool list to the agent unchanged; it neither inspects nor pins descriptions. Whatever a poisoned description makes the agent do is checked like any other call, so calls outside the policy are blocked. No test uses a poisoned description. | Partial |
| **MCP rug pull** (a tool changes after approval) | The firewall turns arguments into the proven action with its own tool catalog, not the server's schema, and the verifier rebuilds the action with its own. If the two disagree, the proof fails to verify. Test: `firewall` › "missing scope: the firewall believes the tool needs a granted scope, the server knows it needs another". A changed description is not detected, and a handler that changes what it does is out of scope (see below). | Partial |
| **Tool shadowing** | `tool_id` hashes the server's identity with the tool name, so a proof for one server or tool is refused by every other. Tests: `firewall` › "a proof made for another server is rejected (tool_id commits to the server)", "a proof for one tool is not accepted for another". Each proxy fronts one upstream server; name collisions between servers are left to the MCP host. No test uses a shadowing description. | Partial |
| **Address poisoning** (lookalike addresses) | The demo attacker's wallet `0x95ba5d…c3d5` shares its first and last characters with the real vendor's. A recipient must be an exact allowlist entry, bound to asset and network, so the lookalike is blocked. Tests: `demo` › "the redirect is blocked for the recipient…"; `firewall` › "same account on another network"; `allowlist.nr` (16 tests). A lookalike the human approves into the allowlist is allowed. | Covered |
| **Proof bound to the exact action** (what you approve is what executes) | The proof commits to the tool and server, scope, amount, recipient and a fresh nonce. A proof moved to another payment is refused, and arguments the proof does not cover are refused. Tests: `demo` › "with a valid proof moved onto a different payment: refused, the proof binds the action"; `firewall` › "a prover that returns a valid proof of a different action is caught by self-verification"; `tools` › "refuses any argument the proof would not cover"; `binding.nr` (13 tests). | Covered |
| **Invisible-text injection** | A demo invoice carries white 1 px text telling AI assistants to pay a 48,750 USDC "full balance". The agent falls for it; the firewall blocks it for exceeding the limit. Tests: `scripted-agent` › "falls for the remittance change and the hidden note, and only those"; `demo` › "the agent was really fooled: it asked for the attacker’s wallet and the inflated amount". Hidden text is not detected, so a hidden instruction for an in-policy payment would succeed. | Partial |
| **Memory poisoning** | The firewall checks every call against the policy whatever the source of the instruction, so a poisoned memory is treated like an injection. The agent process never receives the policy, so its memory cannot leak it. Test: `isolation` › "agent channel: nothing in either direction". No test poisons an agent's memory; the scripted agent has none. | Partial |
| **Proof replay and cross-server replay** | The verifier refuses a binding it has seen, a timestamp outside its window (60 s back, 5 s ahead), and a proof made for another server. Tests: `firewall` › "a replayed call is rejected", "two identical concurrent submissions of one proof execute once", "a stale timestamp is rejected, and so is one from the future", "a proof made for another server is rejected (tool_id commits to the server)"; `demo` › "the same proof again: refused as a replay". The replay store is in memory, per process. | Covered |
| **Policy tampering** | Changing any field of the stored policy changes its commitment, which the verifier has not registered. Registering a commitment takes the owner's passkey over a statement that names it. Tests: `commitment.nr` (19 tests, for example `rejects_overspending_with_a_forged_limit`); `firewall` › "an unregistered commitment is rejected"; `passkey-registry` › "a valid signature over a different statement" (refuses a statement for another commitment); `browser-statement` (the dashboard refuses to sign anything else). | Covered |
| **Limit probing** | The agent sees only an opaque refusal with a decision ID; the reason goes to the operator's log. After 5 refusals in 60 s, protected calls are locked for 300 s. Tests: `firewall` › "the agent learns nothing about why", "locks protected calls after repeated refusals, then recovers"; `prompt-injection` › "a persistent attacker probing the policy is locked out". This slows a search for the limit (about 128 attempts, spec L10) to the order of an hour; it does not prevent it. | Partial |
| **Revocation** | The owner revokes with the passkey. The firewall stops proving, and the verifier refuses even a valid, fresh proof made before the policy's expiry. Revocation is final. Tests: `revocation` › "the firewall, consulting the registry, refuses before proving", "the verifier refuses a valid, fresh, unexpired proof under the revoked policy", "cannot be undone: the verifier will not even issue a registration challenge for it". A revocation landing in the tens of milliseconds between the registry check and the proof check does not stop that one call. | Covered |
| **AI amount errors above the cap** | An amount above the per-payment limit, a zero amount, or a malformed amount is blocked; amounts are never defaulted. Tests: `firewall` › "amount over the limit", "zero amount", "malformed arguments are blocked, never defaulted"; `amount.nr` (11 tests). A wrong amount under the limit, such as 1,000 instead of 100 against a 5,000 limit, is paid. | Partial |
| **Runaway loops** | Every payment is checked on its own (spec L1). The lockout counts refusals only, so a loop of in-policy payments is not stopped. Cumulative budgets are next on the roadmap. | Planned |
| **Compromised plugins calling out-of-scope tools** | A call to a tool whose scope the policy does not grant is blocked, as is any tool that is neither protected nor explicitly passed through. In the demo the agent runs in a sandbox with no network, so it cannot go around the firewall, and a call that reaches the tool server without a proof is refused. Tests: `firewall` › "scope not granted", "an unlisted tool is blocked by default"; `isolation` › "denies file access outside its own code, writes, processes, workers and the network"; `demo` › "without a proof: refused". | Covered |

Key to the tests:

| Name | File |
|---|---|
| `firewall`, `prompt-injection` | [`packages/mcp-firewall/test/`](packages/mcp-firewall/test) `firewall.test.ts`, `prompt-injection.test.ts` |
| `demo`, `revocation`, `isolation`, `passkey-registry`, `browser-statement`, `scripted-agent`, `tools` | [`apps/demo-dashboard/test/`](apps/demo-dashboard/test) `<name>.test.ts` |
| `allowlist.nr`, `amount.nr`, `binding.nr`, `commitment.nr` | [`packages/zk-circuit/crates/proof_of_intent/src/tests/`](packages/zk-circuit/crates/proof_of_intent/src/tests) |

`pnpm dashboard:mutation` removes or weakens each security check of the dashboard in turn and
confirms a test fails (34 of 34). `pnpm run mutation` in `packages/zk-circuit` does the same for
every circuit assertion.

## What this does not protect against

- **Data leakage through tools not routed through the firewall.** Only tools behind the firewall
  are checked. A tool the agent reaches some other way, and a read-only tool you pass through
  without a proof, can carry data out unchecked.
- **Damage a malicious tool does inside its own code.** The verifier checks the call before the
  tool's handler runs. The handler is trusted to execute exactly the call it was given. A
  malicious or compromised tool server can do anything with the resources it controls.
- **Actions inside the policy.** If the policy allows a payment, an injected or mistaken one
  passes. Keep allowlists short and limits low.
- **Whoever runs the prover.** The firewall host holds the policy in the clear while it is armed.

## Compatibility

It works with any agent that calls payment tools over MCP. The firewall is itself an MCP server:
point the agent at it instead of at the tool server, and nothing in the agent changes. The tool
server wraps each payment handler with `requireProofOfIntent`, which needs a few lines (see
[`packages/mcp-firewall`](packages/mcp-firewall)). A tool server that does not verify proofs is
protected only while the agent has no other route to it, and leaves nothing for a third party to
verify.

There is no integration with any closed agent or wallet platform.

Built and tested with `@modelcontextprotocol/sdk` 1.32.2 on Node.js 26.

## Quickstart

You need Node.js 26 and pnpm 12 (`npm install -g pnpm@12`).

```sh
git clone https://github.com/ethqnnn/zk-intent-firewall.git
cd zk-intent-firewall
pnpm install

# The whole demo in the terminal, with a software passkey: approve a policy, run an agent that
# falls for two prompt injections, then revoke. Real proofs, real verification, no browser.
pnpm dashboard:demo -- --revoke

# The same in a browser, with your own passkey (Windows Hello, Touch ID, a security key).
pnpm dashboard:build && pnpm dashboard:start
# Open the printed http://localhost:5173/#token=… URL. Use localhost, not 127.0.0.1.
```

The first run downloads Barretenberg's reference string and caches it. Running the circuit tests
also needs `nargo` 1.0.0; see [Prerequisites](#prerequisites) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- **Cumulative budgets**: daily and per-period totals, and call-count limits, proven against
  committed state rather than per payment only (closes "Runaway loops").
- **An attack lab for testing your own agent**: the injection scenarios in this repo, packaged so
  you can point them at your agent and firewall configuration.
- **Private spending policies for smart wallets**, in Solidity and Rust: the same hidden-policy
  check enforced by the wallet itself.

Also needed before any real use: an external audit, persistent registry and replay store,
encrypted custody of the policy, and passkey recovery.

## Status

| Phase | Part | State |
|---|---|---|
| 1 | Noir circuit, spec, fixtures | Done. Not audited. |
| 2 | TypeScript MCP middleware and verifier SDK | Done. Not audited. See [`packages/mcp-firewall`](packages/mcp-firewall) |
| 3 | Demo dashboard: passkey-approved policies, revocation, live prompt-injection demo | Done. Not audited. See [`apps/demo-dashboard`](apps/demo-dashboard) |

### Known limits

- Per-payment limit only; no cumulative budget (spec L1).
- Registry, replay store and refusal counter are in memory, per process.
- One owner and one passkey; no recovery.
- The policy is stored unencrypted in the owner's browser (IndexedDB).
- Neither the circuit nor its dependencies are audited (spec L11, L12).

[`docs/circuit-spec.md`](docs/circuit-spec.md) sections 8 and 9 and the
[dashboard README](apps/demo-dashboard/README.md#known-limits) list the rest.

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
packages/mcp-firewall/          MCP firewall proxy (prover side) and verifier SDK (tool-server side)
apps/demo-dashboard/            dashboard, passkey registry, sandboxed demo agent
```

## Prerequisites

Exact versions this was built and tested with:

| Tool | Version | Install |
|---|---|---|
| Node.js | 26.13.1 | `.nvmrc` holds the major version |
| pnpm | 12.18.0 | pinned by `packageManager` |
| nargo (Noir) | 1.0.0 | `noirup -v 1.0.0`. Only for the circuit's tests and build |
| bb (Barretenberg) | 5.3.0 | `bbup -v 5.3.0`. Matches the pinned `@aztec/bb.js` 5.3.0; proofs do not cross-verify with 6.0.0. Only for native proving checks |
| `noir-lang/poseidon` | tag `v0.4.0`, commit `e105cdd5c79c222860d53c5dfdb8fa8012b291c0` | fetched by nargo on first use |

## Commands

From the repository root:

| Command | What it does |
|---|---|
| `pnpm test` | `nargo test` on the circuit workspace (152 tests), and the firewall's and the dashboard's vitest suites |
| `pnpm build` | Compile the circuit, build the firewall and the dashboard |
| `pnpm circuit:verify` | Format check, security-path check, tests, dependency pin, fixture check, execute |
| `pnpm firewall:test` | The firewall's vitest suites |
| `pnpm firewall:check:bbjs` | bb.js prove/verify round trip, key hashes, cross-check with native `bb` |
| `pnpm dashboard:build` then `pnpm dashboard:start` | Serve the dashboard on <http://localhost:5173>; open the printed URL |
| `pnpm dashboard:demo` | The demo in the terminal; `-- --revoke` adds revocation |
| `pnpm dashboard:test` | The dashboard's vitest suites (real processes, real proofs) |
| `pnpm dashboard:test:e2e` | Playwright through the dashboard with a virtual authenticator |
| `pnpm dashboard:mutation` | Mutation check of the dashboard's security checks |

[CONTRIBUTING.md](CONTRIBUTING.md) has the full list, including the circuit's mutation check.

## The circuit at a glance

Public inputs, in order: `policy_commitment`, `current_timestamp`, `action_binding`.

| Measure | Value |
|---|---|
| ACIR opcodes (`nargo info`) | 562 |
| Gates (`bb gates`) | 5,237 |
| Poseidon2 permutations | 26 |
| Prove, `bb` 5.3.0, 12 threads | about 230 to 250 ms (`noir-recursive`), 165 to 180 ms (`evm`) |
| Verify | about 9 to 10 ms (`noir-recursive`), 7 ms (`evm`) |
| Proof size | 7,616 bytes (`evm` target) or 14,656 bytes (`noir-recursive` target) |

Read [`docs/circuit-spec.md`](docs/circuit-spec.md) before building on the circuit.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
