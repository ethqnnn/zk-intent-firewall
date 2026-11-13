# @zk-intent-firewall/mcp-firewall

**Status: Phase 2. Working, tested, not audited.**

MCP middleware that blocks an AI agent's sensitive tool calls unless they carry a zero-knowledge
proof that the call obeys a policy a human approved. The proof hides the policy; the tool server
learns only that the call is allowed. The circuit and its contract are in
[`../zk-circuit`](../zk-circuit) and [`docs/circuit-spec.md`](../../docs/circuit-spec.md).

```
agent ──MCP──▶ firewall proxy ───────────── MCP ────────────▶ tool server
               IntentFirewall                                 requireProofOfIntent
               policy opening (private)                       IntentVerifier
               Prover (LocalWasmProver)                       registry, replay store, clock
               self-verification                              pinned verification key
```

## Two parties

**Prover side (`IntentFirewall`, `createFirewallProxy`).** Holds the policy opening, which the
agent can never read. For each tool call it:

1. blocks tools that are neither protected nor explicitly passed through;
2. maps the arguments to the circuit action through the `ToolCatalog` (a malformed amount or
   recipient is blocked, never defaulted) and draws a fresh 248-bit nonce;
3. optionally pre-checks the policy, to refuse early without proving;
4. proves with the injected `Prover`; a circuit assertion failure blocks the call;
5. verifies its own proof against the pinned key, with public inputs it built itself;
6. forwards the call with the proof under `params._meta["zkif/proof-of-intent"]`.

A blocked call is never forwarded. The agent gets an error with an opaque decision ID and no
reason; the reason goes to the operator's `onDecision` hook (spec L10). After repeated refusals,
protected calls are locked out for a while (default: 5 refusals in 60 s, 300 s lockout).

**Verifier side (`IntentVerifier`, `requireProofOfIntent`).** Runs spec 10.3 in full, trusting
nothing from the request except the nonce, the proof, which commitment to check, and a timestamp
it checks against its own clock:

| Step | Check | Rejection |
|---|---|---|
| 1 | Commitment registered and not revoked | `commitment_unknown`, `commitment_revoked` |
| 2 | Timestamp within 60 s before / 5 s after its clock | `timestamp_stale`, `timestamp_in_future` |
| 3 | Action rebuilt from the call and its own catalog (its own server ID in `tool_id`) | `unknown_tool`, `malformed_arguments` |
| 4 | `action_binding` recomputed | |
| 5 | `(commitment, binding)` not seen before | `replayed` |
| 6 | Proof verifies against the pinned key with locally built public inputs | `invalid_proof` |
| 7 | Atomic replay claim, kept until the timestamp would be stale | `replayed` |

## Usage

```ts
import {
  createFirewallProxy, IntentFirewall, IntentVerifier, InMemoryPolicyRegistry, LocalWasmProver,
  PolicyOpening, getHasher, requireProofOfIntent, ToolCatalog, transferTool,
} from '@zk-intent-firewall/mcp-firewall';

// Shared tool definitions and scope registry.
const scopes = { 'payments.send': 3 };
const tools = [transferTool({ name: 'send_payment', scope: 'payments.send', assetId: 'eip155:1/erc20:0xa0b8…eb48' })];
const serverId = 'https://payments.example.com/mcp';

// Firewall (prover side). Load the opening from storage the agent cannot reach.
const policy = PolicyOpening.create(await getHasher(), {
  maxAmount: 500_000_000n,
  recipients: [{ assetId: 'eip155:1/erc20:0xa0b8…eb48', accountId: 'eip155:1:0x4444…4444' }],
  scopes: [3],
  expiry: 1798761600n,
});
const firewall = await IntentFirewall.create({
  policy, prover: await LocalWasmProver.create(),
  catalog: new ToolCatalog({ serverId, tools, scopes }),
  passthroughTools: ['read_invoice'],
  onDecision: (d) => auditLog.write(d),
});
const proxy = createFirewallProxy({ firewall, upstream: connectedClientOfToolServer });
await proxy.connect(transportToTheAgent);

// Tool server (verifier side).
const registry = new InMemoryPolicyRegistry();
registry.register(policy.commitment); // after checking the human's passkey approval (Phase 3)
const verifier = await IntentVerifier.create({ catalog: new ToolCatalog({ serverId, tools, scopes }), registry });
mcpServer.registerTool('send_payment', config, requireProofOfIntent(verifier, 'send_payment', async (args) => pay(args)));
```

## Swapping the prover

The firewall depends only on the `Prover` interface (`src/prover/types.ts`):

```ts
interface Prover {
  readonly name: string;
  prove(request: { inputs: CircuitInputs; target: VerifierTarget }): Promise<IntentProof>;
  destroy(): Promise<void>;
}
```

`LocalWasmProver` implements it with noir_js and bb.js's WASM backend. A hosted prover (Phase 5)
implements the same interface; nothing in the firewall changes. The firewall verifies every proof
it receives for public inputs it computed itself, so a hosted prover cannot return a proof of a
different action. Note that a prover sees the whole policy opening (spec section 2).

## Barretenberg version

The project standardises on **`@aztec/bb.js` 5.3.0** for prover and verifier, with
**`@noir-lang/noir_js` 1.0.0** and native **`bb` 5.3.0** as the matching CLI.

- bb.js 5.3.0 computes verification keys byte-identical to `bb` 6.0.0's, so the hashes in
  `packages/zk-circuit/fixtures/vk_hashes.txt` hold unchanged.
- Proofs do **not** cross-verify between the 5.3.0 and 6.0.0 lines in either direction
  (`UltraVerifier: verification failed at reduction step`). Every prover and verifier must run
  5.3.0.
- `pnpm run check:bbjs` proves and verifies the fixture with bb.js on both targets, checks the key
  hashes and tamper rejection, and cross-verifies with native `bb` when it is on `PATH`.
- `node scripts/sync-circuit.mjs` checks that `circuit/` matches the compiled circuit and that
  `circuit/vk/*.vk` are what bb.js computes. `--write` updates them after a deliberate change.

bb.js downloads Barretenberg's reference string on first use and caches it. bb.js locates its WASM
through a global `__dirname` when one exists, so do not run it from `node -e`, which defines one.

## Commands

| Command | What it does |
|---|---|
| `pnpm test` | vitest: fixture vectors, prover, end-to-end firewall, prompt injection |
| `pnpm run typecheck` | TypeScript over sources and tests |
| `pnpm run build` | Compile to `dist/` |
| `pnpm run check:bbjs` | bb.js round trip and cross-check with native bb |

## Layout

```
circuit/proof_of_intent.json   the compiled circuit (nargo 1.0.0)
circuit/vk/*.vk                pinned verification keys (bb.js 5.3.0), one per zero-knowledge target
src/crypto/                    field encoding, tags, H, allowlist tree, identifiers (spec 5, 10.4)
src/circuit.ts                 circuit loading, pinned keys, typed inputs and their ABI mapping
src/policy.ts                  PolicyOpening: commitment, tree, pre-check, circuit inputs
src/tools.ts                   ToolCatalog: tool call to circuit action
src/envelope.ts                the proof's wire format in params._meta
src/prover/                    Prover interface, LocalWasmProver
src/verifier/                  ProofVerifier, registry, replay store, IntentVerifier
src/firewall.ts                IntentFirewall
src/mcp/                       createFirewallProxy, requireProofOfIntent
test/                          vitest suites and the in-process MCP harness
scripts/                       bb.js round trip, circuit and key sync
```

## Not handled here

- **Passkey approval** (spec D11, L3): `InMemoryPolicyRegistry.register` trusts its caller.
  Verifying the WebAuthn signature over the commitment is Phase 3.
- **Cumulative limits** (L1): each action is checked alone.
- **Persistent and shared state**: the registry and replay store are in-memory, per process.
  `ReplayStore.claim` must be atomic in a shared implementation.
- **Verifier-issued nonces**: the firewall draws its own nonce; a server that issues nonces would
  need a round trip before proving.
