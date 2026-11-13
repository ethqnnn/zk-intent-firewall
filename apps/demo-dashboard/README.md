# @zk-intent-firewall/demo-dashboard

**Status: Phase 3. Demo-ready, not audited, not custody for real funds.**

The human side of the firewall. A person writes a policy and approves it with a passkey, then
watches a scripted agent work through an inbox that an attacker can write to. The real firewall
proves the legitimate payments and a separate tool-server process verifies them. The same firewall
blocks the injected ones. Revoking the policy with the passkey stops it at once, long before it
expires.

Nothing in the demo path is mocked:

- the proofs are real UltraHonk proofs (14,656 bytes, `noir-recursive`);
- the verifier is `IntentVerifier` from `packages/mcp-firewall`, running in its own process;
- the approval is a WebAuthn assertion, checked with `@simplewebauthn/server`.

## Run it

From `apps/demo-dashboard` (or with `pnpm --filter @zk-intent-firewall/demo-dashboard run …` from
the root):

| Command | What it does |
|---|---|
| `pnpm build && pnpm start` | Build the web app and serve it from `dist/`, on <http://localhost:5173> |
| `pnpm dev` | The same through Vite, with hot reload |
| `pnpm demo` | The whole demo without a browser: enrol, approve, arm, run; prints the transcript |
| `pnpm demo --revoke` | Then revoke with the passkey and run again with a firewall that ignores the registry |
| `pnpm demo --json` | The run results as JSON |
| `pnpm test` | Vitest: unit and integration suites, real processes (about 17 s) |
| `pnpm test:e2e` | Build, then Playwright drives the dashboard with a virtual authenticator (about 20 s) |
| `RECORD=1 pnpm test:e2e` | The same, keeping a video of the run in `test-results/` (usable as the demo recording) |
| `SHOTS=dir pnpm test:e2e` | The same, saving a screenshot per step into `dir` |
| `pnpm mutation` | Mutation check of the security checks; prints the table below (about 90 s) |
| `pnpm typecheck` | Both TypeScript programs (Node and browser) |

`start` and `dev` print a URL such as `http://localhost:5173/#token=…`. The token in the fragment
is the key to the API. The page moves it into `sessionStorage` and removes it from the address
bar. Use `localhost`, not `127.0.0.1`: WebAuthn needs a domain as RP ID, and `localhost` is a
secure context. `--port=N` or `ZKIF_PORT` changes the port, `ZKIF_SESSION_TOKEN` fixes the token,
and `ZKIF_DEBUG=1` shows the child processes' output.

Any platform passkey works: Windows Hello, Touch ID, Android, or a security key. The verifier
requires user verification.

## Architecture

```
 Browser (policy owner)                     Host process: src/server/host
 ┌──────────────────────────────┐   HTTP    ┌──────────────────────────────────────────┐
 │ React dashboard              │ ────────▶ │ Dashboard API (token, same-origin, JSON)  │
 │ IndexedDB: policy openings   │  loopback │ Firewall: IntentFirewall + LocalWasmProver│
 │ Passkey (WebAuthn)           │           │   holds the armed opening in memory only  │
 └──────────────────────────────┘           └──────┬─────────────────────────┬──────────┘
                                            IPC: MCP│                         │IPC: MCP + RPC
                                                    ▼                         ▼
                                 Agent process: src/agent          Tool server: src/server/verifier
                                 node --permission, sandboxed      PasskeyPolicyRegistry
                                 scripted LLM stand-in             IntentVerifier (pinned keys)
                                 no files, no network,             treasury tools: list_inbox,
                                 no processes, empty env           read_message, send_payment
```

Three operating-system processes, so each trust boundary is a process boundary:

- **The host** serves the dashboard and runs the firewall: the prover side. It holds the policy
  opening only while it is armed, in memory. A host restart disarms it.
- **The tool server** is the verifier. It holds the registry of approved commitments and the
  passkey that approves them. It never receives a policy opening. Every `send_payment` passes
  `requireProofOfIntent` before the payment executes. Read-only inbox tools pass through without a
  proof, so injected text can reach the agent, as it would in practice.
- **The agent** is a scripted stand-in for an LLM, forked per run under Node's permission model.
  It can read its own code and installed packages and talk MCP over its IPC channel, and nothing
  else (see `src/server/host/sandbox.ts`). It is written to fall for two indirect prompt
  injections:
  - a remittance-change notice from a lookalike domain, pointing to an address-poisoning wallet;
  - white-on-white text telling AI assistants to pay a 48,750 USDC "full balance".

### The scenario

| Message | What the agent does | Firewall | Tool server |
|---|---|---|---|
| Northwind NW-2041, 1,250 USDC | Pays the invoice | Proves (about 300 to 600 ms) | Verifies (14 to 36 ms), pays |
| "Northwind" NW-2042, new wallet, 2,980 USDC | Pays the attacker's lookalike address | Blocks: `recipient_not_allowlisted` | Never sees it |
| Contoso CC-88317, 3,400 USDC with a hidden note | Pays 48,750 USDC | Blocks: `amount_exceeds_limit` | Never sees it |
| Fabrikam FB-1102, 412.60 USDC | Pays the invoice | Proves | Verifies, pays |

The preset policy allows up to 5,000 USDC per payment to four payees. One of them, Litware, is
never paid or mentioned, so the tests can check that nothing in the run reveals it. The scope is
`payments.send`, for 30 days. The agent sees only an opaque refusal with a decision ID. The reason
goes to the operator's audit log.

## Where the policy lives

The opening (limit, allowlist, scopes, expiry and the secret salt) is the policy. The commitment
reveals nothing about it, as long as the salt stays secret.

| Place | What is there | When |
|---|---|---|
| The owner's browser, IndexedDB `zkif-dashboard` / `policies` | Opening, commitment and payee labels | At rest, until deleted from the dashboard |
| Host process memory | The opening | Briefly while computing the commitment (nothing kept); for as long as the firewall is armed |
| Tool server | The commitment, its status and the passkey's public key | Always; never the opening |
| Agent process | Nothing about the policy | Cannot read files or the network; receives tool results and opaque refusals |

The salt is drawn in the browser, 248 bits from `crypto.getRandomValues`. The host refuses a salt
under 2^128. The commitment is computed on the host because the Poseidon2 hashing runs on
mcp-firewall's Node-only stack, which this phase does not modify. The host keeps nothing from
that request.

This is a demo arrangement, not custody:

- IndexedDB is plaintext in the browser profile. It is readable by anything running as the same OS
  user, and by any script that runs on this origin. The CSP (`script-src 'self'`) and the absence
  of third-party code limit the second risk; nothing addresses the first.
- The host holds the armed opening in ordinary memory.
- There is no backup and no recovery. If the browser profile is lost, the policy is lost, and a new
  one has to be approved.

**Phase 5 needs encrypted server-side custody.** The hosted product proves on the server. The
opening must be encrypted at rest under a key held in a KMS or HSM, scoped per tenant, and
decrypted only inside the prover, ideally in an attested enclave. Access must be audited, and
backup and recovery must keep it encrypted. One step short of that is to encrypt the browser copy
under a key derived with the WebAuthn PRF extension from the same passkey, so that the opening at
rest needs the user's authenticator. That was left out here because PRF support across platforms
is uneven.

## Passkey approval

This closes the trust gap in Phase 2. There, `InMemoryPolicyRegistry.register` activated any
commitment it was given. Here the registry is `PasskeyPolicyRegistry`
(`src/server/verifier/passkey-registry.ts`). It wraps that class privately and exposes only two
ways to change state: `approveRegistration` and `approveRevocation`. Each needs a WebAuthn
assertion from the enrolled owner over a statement the verifier builds itself. The firewall, the
dashboard and the agent can only read the registry.

### What is signed

The design follows spec D11 and L3 (the signature is verified off-circuit, by the verifier) and
10.5 (sign more than the bare commitment):

```
zkif.policy-approval.v1
action: register
policy_commitment: 0x1704d956…2637f308
vk_hash.evm: 0x0ada696cfd9ba778ed3c2b4d1cb79a4efc0e9a389f2561cd86d6f5b1eba9557b
vk_hash.noir-recursive: 0x15bd93c9bb5f2c9bfe73268360c1a69892eb13777e084bdc282d2125fb6cb3de
nonce: tVcz5Dit57REwD4cwOyI980nAsTxtMXRLNjXjI2XY9M
```

- **The protocol label.** A signature for this protocol cannot be read as anything else.
- **The action.** A registration approval cannot be replayed as a revocation, or the other way
  round.
- **The commitment.** The approval covers this policy and no other.
- **The hash of every verification key the verifier accepts.** The approval cannot be carried over
  to another circuit or key. The key hashes are pinned in the browser bundle, in mcp-firewall and
  in `vk_hashes.txt`, and a test checks that all three agree.
- **A nonce from the verifier.** It is 32 random bytes and lives 300 s. It is bound to the action
  and commitment it was issued for, and consumed by the first attempt, even a failed one.

The WebAuthn challenge is `base64url(SHA-256(statement text))`. The text is canonical: fixed
lines, key hashes sorted by target, strict formats. Anything off-format is refused rather than
encoded.

### What the verifier checks, in order

1. The commitment is a field element and an owner is enrolled.
2. The nonce exists. It is then deleted. It has not expired, and it was issued for this action and
   this commitment.
3. The response is a well-formed assertion, and its credential ID is the enrolled owner's.
   simplewebauthn does not check this, so this code does.
4. The statement and challenge are rebuilt from the verifier's own state: label, action,
   commitment, pinned key hashes and nonce. Nothing is taken from the request.
5. `verifyAuthenticationResponse` checks:
   - type `webauthn.get`;
   - the challenge;
   - an origin in the allowed list;
   - the RP ID hash;
   - user presence and user verification;
   - the ECDSA P-256 or RSA signature over `authenticatorData ‖ SHA-256(clientDataJSON)`;
   - that the signature counter has not regressed.
6. The result must be `verified === true` with `userVerified === true`. simplewebauthn returns
   false rather than throwing in some cases, and both are handled.
7. The counter is stored. For registration, a revoked commitment is refused: revocation is final.

**Enrolment** is trust on first use. The first passkey enrolled through the dashboard, which
requires the session token, becomes the owner, and enrolment then closes. The verifier requires
user verification and accepts ES256 and RS256.

**The browser checks too.** Before it asks the passkey to sign, the dashboard rebuilds the
statement and challenge from the commitment it holds and the key hashes it pins. It refuses unless
they match exactly what the verifier relayed. A relay cannot get the passkey to sign anything
else, even one that recomputes the text and challenge consistently over an altered statement.

### Revocation

Revocation is a passkey-approved `revoke` statement. It takes effect in the registry, which both
sides consult:

- **The firewall** checks the registry before it proves, and blocks with `policy_not_active`.
- **The verifier** refuses with `commitment_revoked`, even for a proof that is cryptographically
  valid, fresh, unreplayed and well before the policy's expiry.

The demo's "Simulate a firewall that ignores revocation" switch, and `pnpm demo --revoke`, show the
second case. `test/revocation.test.ts` checks that the proof the verifier refused verifies
independently.

## Security checks and their tests

| Suite | Tests | Covers |
|---|---|---|
| `approval.test.ts` | 7 | Canonical statement and challenge. Every field changes the challenge. Malformed statements are refused. The three copies of the key hashes agree. |
| `passkey-registry.test.ts` | 46 | Enrolment (trust on first use, challenge, origin, RP ID, UV, expiry). Missing or malformed approvals. Signatures that do not verify (bit flips, other key, tampered data, wrong origin, RP ID or type, no UV, no UP). Valid signatures over another commitment, key hash, set of keys, label, protocol, action or nonce, or a client-chosen challenge. Nonce replay, burning and expiry. Unknown credential. Counter regression. Revocation being final. |
| `browser-statement.test.ts` | 9 | The dashboard refuses to sign another label, action, commitment or set of key hashes, or a mismatched text or challenge. |
| `revocation.test.ts` | 6 | Register, pay, revoke. Then the firewall refuses, the verifier refuses an independently valid proof before expiry, a direct call to the tool server is refused, and re-registration is refused. |
| `isolation.test.ts` | 14 | The sandbox denies reads, writes, processes, workers and the network, against an unsandboxed control. No policy value appears on either IPC channel, in the audit log, in the event stream or in any GET response. The API's token, origin and content-type guards. The salt floor. |
| `demo.test.ts` | 14 | The run's outcomes. Blocked calls are never forwarded. Refusals are opaque. The ledger. Direct calls with no proof, a garbled, moved, tampered or replayed proof, with an untouched proof as control. A permissive policy lets the same attacks through (anti-stub). With the precheck off, the circuit refuses on its own. |
| `scripted-agent.test.ts` | 4 | Inbox parsing, pinned so that the injections keep firing. |
| `tools.test.ts` | 3 | `send_payment` binds amount and recipient, and refuses unbound arguments and malformed accounts. |
| `e2e/dashboard.spec.ts` | 2 | The whole flow in Chromium with a CDP virtual authenticator, and the API refusing requests without the token. |

### Mutation check

`pnpm mutation` removes or weakens one check at a time, runs the tests that should notice, and
restores the source. It refuses to run if a mutation no longer applies exactly once, or if the
unmutated tests fail.

Each mutant weakens its check the way a real bug would, without breaking anything else. A mutant
that also made valid approvals fail would be killed for the wrong reason. So, for example, the
origin mutant trusts the origin the client claims rather than switching the check off. Some checks
have two layers, such as the registry's revoked check and the nonce issuer's. Those mutants remove
both layers, because removing one leaves the other to hold the line.

Some checks happen inside `@simplewebauthn/server` and cannot be switched off without breaking
every verification:
- the RP ID hash;
- the `webauthn.get` type;
- the signature itself.

These are covered by direct tests instead, in `passkey-registry.test.ts`: a foreign RP ID, a
`webauthn.create` type, and a flipped bit, another key or tampered data.

| # | Check removed or weakened | File | Result | Failing tests (first) |
|---|---|---|---|---|
| R1 | Approval nonce is single use | `server/verifier/passkey-registry.ts` | killed | 2: registration approval nonces an approval is accepted once: a replay of the same signed request is refused |
| R2 | Approval nonce expires | `server/verifier/passkey-registry.ts` | killed | 1: registration approval nonces refuses an expired nonce |
| R3 | Nonce is bound to the action and commitment it was issued for | `server/verifier/passkey-registry.ts` | killed | 1: registration approval nonces refuses a nonce issued for another commitment or action |
| R4 | Assertion comes from the enrolled credential | `server/verifier/passkey-registry.ts` | killed | 1: registration approval refuses an assertion from a credential that is not the enrolled owner |
| R5 | Challenge is rebuilt from verifier state, not taken from the client | `server/verifier/passkey-registry.ts` | killed | 10: registration approval a valid signature over a different statement refuses a statement for another commitment |
| R6 | Signed statement covers every accepted VK hash | `server/verifier/passkey-registry.ts` | killed | 1: registration approval the issued statement names the label, the action, the commitment and both pinned keys |
| R8 | Signature verification result is enforced | `server/verifier/passkey-registry.ts` | killed | 6: registration approval a signature that does not verify refuses one flipped bit in the signature |
| R9 | User verification is required (both layers) | `server/verifier/passkey-registry.ts` | killed | 1: registration approval a signature that does not verify refuses no user verification (UV flag clear) |
| R10 | Assertion origin is checked against the configured origins, not the client’s claim | `server/verifier/passkey-registry.ts` | killed | 1: registration approval a signature that does not verify refuses a foreign origin |
| R12 | Signature counter is tracked (cloned authenticator) | `server/verifier/passkey-registry.ts` | killed | 1: registration approval refuses a signature counter that went backwards (cloned authenticator) |
| R13 | A revoked commitment cannot be registered again (both layers) | `server/verifier/passkey-registry.ts` | killed | 2: revocation approval a valid owner signature revokes, and revocation is final |
| R14 | Enrolment is trust-on-first-use only (both layers) | `server/verifier/passkey-registry.ts` | killed | 1: enrolment records the owner credential once; a second enrolment is refused (trust on first use) |
| R15 | Enrolment challenge expires | `server/verifier/passkey-registry.ts` | killed | 1: enrolment refuses an enrolment that was never started, or has expired |
| R16 | Revocation reaches the registry | `server/verifier/passkey-registry.ts` | killed | 5: revocation revoke: needs a passkey signature over the revoke statement |
| S1 | Statement text includes the nonce | `shared/approval.ts` | killed | 3: approval statement has a fixed, line-based canonical form with the key hashes sorted by target |
| S2 | Statement text includes the VK hashes | `shared/approval.ts` | killed | 4: approval statement has a fixed, line-based canonical form with the key hashes sorted by target |
| S3 | Statement text includes the action | `shared/approval.ts` | killed | 4: approval statement has a fixed, line-based canonical form with the key hashes sorted by target |
| S4 | Statement text includes the protocol label | `shared/approval.ts` | killed | 4: approval statement has a fixed, line-based canonical form with the key hashes sorted by target |
| B1 | Browser refuses to sign: protocol label mismatch | `web/passkey.ts` | killed | 1: the dashboard refuses to sign anything but the requested approval refuses another label, even with matching text and challenge |
| B2 | Browser refuses to sign: action mismatch | `web/passkey.ts` | killed | 1: the dashboard refuses to sign anything but the requested approval refuses another action, even with matching text and challenge |
| B3 | Browser refuses to sign: policy commitment mismatch | `web/passkey.ts` | killed | 1: the dashboard refuses to sign anything but the requested approval refuses another commitment, even with matching text and challenge |
| B4 | Browser refuses to sign: pinned VK hashes mismatch | `web/passkey.ts` | killed | 3: the dashboard refuses to sign anything but the requested approval refuses another key hash, even with matching text and challenge |
| B5 | Browser refuses to sign: displayed text mismatch | `web/passkey.ts` | killed | 1: the dashboard refuses to sign anything but the requested approval refuses display text that differs from the statement |
| B6 | Browser refuses to sign: challenge mismatch | `web/passkey.ts` | killed | 1: the dashboard refuses to sign anything but the requested approval refuses a challenge that is not the statement’s |
| T1 | send_payment executes only with a verified proof | `server/verifier/treasury.ts` | killed | 3: the scripted attack against the preset policy calling the treasury directly, around the firewall without a proof: refused |
| T2 | send_payment refuses arguments the proof does not bind | `server/tools.ts` | killed | 1: send_payment refuses any argument the proof would not cover |
| F1 | Firewall consults the registry before proving | `server/host/firewall-host.ts` | killed | 1: revocation the firewall, consulting the registry, refuses before proving |
| F2 | Policy salt carries at least 128 bits | `server/host/host.ts` | killed | 1: no policy value leaves the browser and the firewall a policy needs a salt of at least 128 bits, drawn in the browser |
| H1 | API requires the session token | `server/host/host.ts` | killed | 1: no policy value leaves the browser and the firewall dashboard API guards no token or a wrong token: 401, on GET and POST |
| H2 | POST requires same origin | `server/host/http.ts` | killed | 2: no policy value leaves the browser and the firewall dashboard API guards another origin, or none: 403 |
| H3 | POST requires a JSON content type | `server/host/http.ts` | killed | 2: no policy value leaves the browser and the firewall dashboard API guards a non-JSON body (a form post, for example): 415 |
| X1 | Agent runs under the permission model | `server/host/sandbox.ts` | killed | 3: agent sandbox denies file access outside its own code, writes, processes, workers and the network |
| X2 | Agent read access is limited to its own code | `server/host/sandbox.ts` | killed | 1: agent sandbox denies file access outside its own code, writes, processes, workers and the network |
| X3 | Agent does not inherit the host's environment | `server/host/sandbox.ts` | killed | 1: agent sandbox denies file access outside its own code, writes, processes, workers and the network |

34 of 34 mutants killed.

The firewall's log sanitiser (`toLogEntry`) drops the `detail` field of decisions as a precaution.
There is no mutant for it: today's details carry no policy values, so re-adding the field would be
an equivalent mutant. The isolation suite would catch a detail that started to.

## Known limits

**Fine for a demo:**

- **One owner, one browser.** There are no multiple approvers, no thresholds and no key rotation.
  A lost passkey means re-enrolling, which needs a fresh tool-server state.
- **State is in memory.** The registry, ledger and nonces are lost when the processes restart, and
  the dashboard then shows its stored policies as unregistered.
- **A small TOCTOU window.** In `IntentVerifier`, the registry is read before the proof is verified
  (tens of milliseconds). A revocation that lands in between does not stop that one call. A
  production verifier would re-check the status atomically with execution.
- **The agent is scripted.** It is deterministic, for repeatable tests and video. A real LLM
  behind the same firewall would be stopped by the same checks, which never consult the agent.

**Needed for Phase 5:**

- encrypted server-side custody of the opening;
- persistent registry and replay store;
- multi-device and recovery for the owner's passkey, possibly several approvers;
- authenticator attestation, if the operator wants to restrict which authenticators qualify;
- a hosted prover with tenant isolation;
- an audit trail of approvals.

## Dependencies

Exact versions, pinned in `package.json`:

| Package | Version | Why |
|---|---|---|
| `@modelcontextprotocol/sdk` | 1.32.2 | MCP client and server over the IPC channels |
| `@simplewebauthn/server` | 14.1.0 | WebAuthn registration and assertion verification |
| `@simplewebauthn/browser` | 14.0.0 | WebAuthn ceremonies in the dashboard |
| `react`, `react-dom` | 19.3.1 | Dashboard UI |
| `zod` | 4.6.7 | Tool input schemas (MCP SDK peer) |
| `vite` | 8.3.8 | Dev server and build |
| `@vitejs/plugin-react` | 6.3.0 | |
| `tailwindcss`, `@tailwindcss/vite` | 4.3.5 | Styles |
| `typescript` | 7.0.2 | Type checking (the server runs on Node's type stripping) |
| `vitest` | 5.0.5 | Unit and integration tests |
| `@playwright/test` | 1.61.0 | End-to-end test and video |
| `@types/node` | 26.6.6 | |
| `@types/react`, `@types/react-dom` | 19.3.0 | |

The proving and verification stack comes from `packages/mcp-firewall`: `@aztec/bb.js` 5.3.0 and
`@noir-lang/noir_js` 1.0.0.
