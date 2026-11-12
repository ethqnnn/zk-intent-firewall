# @zk-intent-firewall/demo-dashboard

**Status: placeholder. No code yet. This app is Phase 3.**

The demo dashboard is the human-facing side of the firewall: the place where a person defines what
an agent may do and approves it.

## Phase 3 scope

- **Policy editor.** Set the per-action spending limit, the recipient allowlist, the allowed
  action scopes and the expiry. The dashboard builds the allowlist Merkle tree and the policy
  commitment using the Phase 2 library.
- **Passkey approval.** The human signs the policy commitment with a passkey (WebAuthn, P-256).
  The signed commitment is what verifiers register. The policy itself never leaves the prover
  side.
- **Live demo.** Run an agent against a mock payment tool server and show, call by call, which
  actions produced a valid proof and which were blocked, including a prompt-injection attempt that
  tries to pay a recipient outside the allowlist.
- **Verifier view.** Show what the tool server actually sees: the commitment, the action and a
  proof, and nothing about the limit, the rest of the allowlist, the other scopes or the expiry.

## Depends on

- [`packages/zk-circuit`](../../packages/zk-circuit): the Noir circuit (Phase 1, done).
- [`packages/mcp-firewall`](../../packages/mcp-firewall): the TypeScript middleware and verifier
  SDK (Phase 2).

## Not in this app

Team management, hosted proving and compliance audit logs are the paid SaaS layer, not the open
demo.
