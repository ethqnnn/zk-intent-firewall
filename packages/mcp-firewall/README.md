# @zk-intent-firewall/mcp-firewall

**Status: placeholder. No code yet. This package is Phase 2.**

The MCP firewall is the TypeScript middleware that sits between an AI agent and the MCP tool
servers it calls. Before a sensitive tool call leaves the agent side, the firewall proves in zero
knowledge that the call obeys a policy a human approved, without revealing the policy.

The circuit it drives is finished and lives in [`../zk-circuit`](../zk-circuit). Its contract is
[`docs/circuit-spec.md`](../../docs/circuit-spec.md). Read section 10 of the spec ("Phase 2
integration notes") before writing any code here.

## Phase 2 scope

Prover side (this package):

- An MCP interceptor that recognises sensitive tool calls and maps each one to the circuit's
  `Action` (`tool_id`, `scope_index`, `amount`, `recipient`, `nonce`).
- Policy tooling: build the recipient allowlist Merkle tree, compute the policy commitment, and
  keep the policy opening (limit, allowlist, scopes, expiry, salt) out of reach of the agent.
- Witness generation with `@noir-lang/noir_js` and proving with Barretenberg, using a
  zero-knowledge verifier target.
- A transport convention for attaching the proof, the timestamp and the nonce to a tool call.

Verifier side (a small SDK for tool servers, payment gateways and audit logs):

- Rebuild the three public inputs from the verifier's own view of the call. Never accept them from
  the prover.
- Check that the timestamp is fresh, that the nonce is unused, and that the policy commitment is
  registered and not revoked.
- Verify the passkey (WebAuthn, P-256) signature a human made over the policy commitment. This
  happens off-circuit; the spec explains why.

## First task

Make the TypeScript implementation reproduce
[`../zk-circuit/fixtures/vectors.json`](../zk-circuit/fixtures/vectors.json) exactly: every leaf
hash, the Merkle root, the policy commitment and the action binding. Those values were generated
by the Noir code. Until they match, nothing else in this package can be trusted.

## Out of scope for Phase 2

The hosted proving API, the team policy dashboard and compliance audit logs belong to the paid
SaaS layer and come later.
