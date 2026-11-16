# @zk-intent-firewall/break-it

**A public "break it" environment. FAKE MONEY: no real funds, no payment rail, no blockchain.**

The real circuit, the real firewall and prover, the real passkey-gated registry and the real
verifier, running as a public web service against a fake ledger. Strangers can attack the actual
system without anyone's money at risk. Every attempt is logged publicly with the check that
caught it, and anything the system accepts that the published policy does not allow is flagged as
a break.

## What runs

```
 internet ──HTTP──▶ front process (src/front)                 engine process (src/engine), sandboxed
                    rate limits, gates, body limits ──IPC──▶  IntentFirewall + LocalWasmProver   (per visitor)
                    public log (JSON lines on a volume)       IntentVerifier + requireProofOfIntent
                    static pages (public/)                    PasskeyPolicyRegistry
                                                              fake ledger, break detector
```

Nothing on the security path is re-implemented. The engine imports, unchanged:

| From | What |
|---|---|
| `packages/mcp-firewall` | `IntentFirewall`, `createFirewallProxy`, `LocalWasmProver`, `IntentVerifier`, `requireProofOfIntent`, `ProofVerifier`, `PolicyOpening`, the compiled circuit and pinned keys |
| `apps/demo-dashboard` | `PasskeyPolicyRegistry`, `SoftAuthenticator`, the `sendPayment` tool spec, `canonicalAccount`, the IPC channel |

What is new here is only what a public, fake-money instance needs: the ledger
(`src/engine/ledger.ts`), the break detector (`src/engine/oracle.ts`), the wiring
(`src/engine/engine.ts`, `src/engine/tool-server.ts`), and the public front (`src/front`, `public/`).

### The policy in force

Published on the page and at `GET /api/status`, except for the salt:

| Field | Value |
|---|---|
| Per-payment limit | 500 fake USDC |
| Allowlist | Northwind, Contoso, Fabrikam (the demo payees) |
| Scopes | `payments.send` only (`treasury_sweep` needs `treasury.admin`, not granted) |
| Expiry | 90 days after the instance started |
| Salt | secret, drawn at boot, never leaves the engine |
| Treasury | opens at 10,000 fake USDC; topped back up when it falls below 500 |

### The owner

At boot the engine creates a software passkey (a real P-256 key), enrols it as the owner, approves
the published policy through the registry's normal approval path, and drops it. After boot no
owner key exists, so no request can get an approval signed. Any registration, revocation or
enrolment accepted after that is a break by definition.

### Attack routes

| Route | Endpoint | What you are |
|---|---|---|
| Agent | `POST /api/attempt/agent` `{tool, arguments, mode?, precheck?}` | The AI agent, or the injection steering it. `mode: "prove-only"` returns an unspent proof; `precheck: false` leaves every decision to the circuit. |
| Direct | `POST /api/attempt/direct` `{tool, arguments, meta?}` | A caller going around the firewall to the tool server, with any `_meta` (proof envelope under `zkif/proof-of-intent`). |
| Passkey | `GET /api/passkey/challenge?action=&policyCommitment=`, then `POST /api/attempt/passkey` `{action, policyCommitment, nonce, response}` | Someone trying to register their own policy or revoke the published one. |
| Enrol | `POST /api/attempt/enroll` `{stage: "options" \| "complete", response?}` | Someone trying to enrol a second owner passkey. |

Every POST may also carry `handle` (shown on the leaderboard) and `note` (what you are trying).
Reads: `GET /api/status`, `GET /api/log?limit=&before=&verdict=&route=&layer=&check=&who=`,
`GET /api/log?id=`, `GET /api/leaderboard`, `GET /api/whoami`, `GET /healthz`.

### What counts as a break

The break detector (`src/engine/oracle.ts`) checks every payment the verifier accepted, and every
proof the firewall issued, against the published policy. It uses plain comparisons: no circuit, no
hashing, no `ToolCatalog`. It flags:

- a recipient not exactly on the allowlist;
- an amount of zero, an amount over the limit, or a paid amount that differs from the requested one;
- a tool whose scope is not granted, or an argument the proof does not bind;
- a time at or after expiry, or any commitment other than the published one;
- the same `(commitment, binding)` executed twice.

Separately, any accepted passkey approval or enrolment is a break. The detector cannot see two
kinds of break, which must be reported by hand: a leak of the salt or opening, and the engine
escaping its sandbox.

In-policy payments, draining by repetition (there is no cumulative budget, spec L1), seeing the
operator's refusal reason, and hitting rate limits are not breaks. The page says so.

## Abuse protection

- **Engine sandbox.** The engine runs under `node --permission` with read access to its own code,
  its imports and the reference-string cache. It may write only to that cache, and may start worker
  threads (bb.js needs them; workers inherit the restrictions). Everything else is denied: the
  network, child processes, addons, the inspector and WASI. Its environment has five variables.
  Node's network permission is all or nothing, which is why the process that listens is a separate
  one. At boot the front asks the engine to open a connection, fetch, start a process, write a file
  and read `/etc/passwd`, and refuses to serve unless all five fail with `ERR_ACCESS_DENIED`. The
  result is shown on the page. The network probes target 192.0.2.1 (TEST-NET-1), so even a broken
  sandbox sends nothing anywhere real.
- **Outbound code.** `test/egress.test.ts` fails if any source file gains outbound-network code. The
  front makes no outbound calls.
- **Per-visitor rate limits** (token buckets, keyed by an HMAC of the client address under a
  per-boot secret): agent 6/min, direct 20/min, passkey 10/min, reads 120/min.
- **Global proving budget**: 30 agent attempts per minute across everyone, burst 20.
- **Concurrency gates**: at most 2 agent attempts run (proofs are made one at a time) and 6 wait;
  the rest get `503` at once. Direct attempts: 4 run, 16 wait.
- **Per-visitor firewall**: one visitor tripping the firewall's lockout (5 refusals in 60 s, then
  300 s) locks out only themselves. At most 500 visitor sessions are kept.
- **HTTP**: 128 KiB bodies, JSON-only POSTs, a same-origin check whenever a browser sends `Origin`,
  15 s header and 90 s request timeouts, and a V8 heap cap for the engine (1536 MB).
- **Pages**: no third-party code, CSP `default-src 'none'; script-src 'self'; …`, and no
  `innerHTML`. Logged strings come from strangers.

## Deploy on Railway

The service is one Docker image built from the repository root, and must run as **one replica**:
the registry, ledger and replay store are in memory. Railway's `railway.json`/`railway.toml` (Config
as Code) is deprecated and stops being read on 2026-12-01, so this package has none. The settings
below go in the dashboard.

1. **New service from the repo.** In a Railway project: *New* → *GitHub Repo* →
   `ethqnnn/zk-intent-firewall`. Leave *Root Directory* empty: the build needs the whole workspace.
2. **Point it at the Dockerfile.** *Variables* → add `RAILWAY_DOCKERFILE_PATH` =
   `apps/break-it/Dockerfile`.
3. **Add a volume** for the attempt log: right-click the service → *Attach volume*, mount path
   `/data`. Then add the variables `BREAKIT_DATA_DIR` = `/data` and `RAILWAY_RUN_UID` = `0`.
   Railway mounts volumes as root and the image runs as `node`. Without `RAILWAY_RUN_UID=0` the
   service still runs, but the log stays in memory and the boot log says so.
4. **Public domain.** *Settings* → *Networking* → *Generate Domain* (target port: the one Railway
   sets in `PORT`, by default 8080). The service reads `RAILWAY_PUBLIC_DOMAIN` and uses
   `https://<domain>` as its origin. With a custom domain, set `BREAKIT_PUBLIC_ORIGIN` =
   `https://your.domain`. The origin is the WebAuthn RP ID and is hashed into every `tool_id`, so it
   must be the address people actually use.
5. **Health check and restarts.** *Settings* → *Deploy*: *Healthcheck Path* `/healthz`,
   *Restart Policy* `On Failure`. Keep *Replicas* at 1. If the engine process dies, the service
   exits so that Railway restarts it.
6. **Resources.** The engine holds about 850 MB once it has proved (measured: 820 MB RSS), the front
   under 100 MB. Give the service at least 2 GB, and set
   `BREAKIT_PROVER_THREADS` to the vCPUs you allot (default 2).
7. **Deploy**, then open the domain. In the deploy log, look for
   `engine sandbox holds: {"network":"ERR_ACCESS_DENIED",…}` and `policy in force: 0x…`.
8. **Check the client address.** Rate limits key on the right-most `X-Forwarded-For` entry, the one
   Railway's edge adds. Railway's documentation and forum answers disagree on these headers, so check
   your deployment. `curl https://<domain>/api/whoami` and the same with
   `-H 'X-Forwarded-For: 1.2.3.4'` must print the same `who`. If they differ, set
   `BREAKIT_CLIENT_IP_SOURCE` = `x-real-ip` and check again.

Each push to `main` redeploys. A redeploy starts a new instance: new salt, new commitment, a fresh
ledger. The log persists on the volume, and each record names the commitment of the instance it
hit.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 8080 | Set by Railway |
| `BREAKIT_PUBLIC_ORIGIN` | `https://$RAILWAY_PUBLIC_DOMAIN`, else `http://localhost:$PORT` | Public origin |
| `BREAKIT_DATA_DIR` | `$RAILWAY_VOLUME_MOUNT_PATH`, else unset (memory only) | Where `attempts.jsonl` is kept |
| `BREAKIT_CRS_PATH` | `/app/crs` in the image, `~/.bb-crs` otherwise | Barretenberg reference string, fetched at build time |
| `BREAKIT_PROVER_THREADS` | 2 | WASM proving threads |
| `BREAKIT_ENGINE_MAX_OLD_SPACE_MB` | 1536 | Engine heap cap |
| `BREAKIT_AUTO_TOP_UP` | 1 | 0 lets the treasury run dry |
| `BREAKIT_CLIENT_IP_SOURCE` | `x-forwarded-for` on Railway, else `socket` | Also `x-real-ip` |
| `BREAKIT_PROXY_HOPS` | 1 | Proxies in front, for `x-forwarded-for` |
| `BREAKIT_LIMIT_{AGENT,DIRECT,PASSKEY,READ,GLOBAL_PROVING}_{BURST,PER_MINUTE}` | 6/6, 20/20, 10/10, 120/120, 20/30 | Rate limits |
| `BREAKIT_GATE_{AGENT,DIRECT}_{CONCURRENCY,QUEUE}` | 2/6, 4/16 | Concurrency gates |
| `BREAKIT_DEBUG` | unset | 1 shows the engine's output |

## Run it locally

From this directory, with Node.js 26 and pnpm 12, after `pnpm install` at the root:

```sh
pnpm build                 # builds packages/mcp-firewall
pnpm start                 # http://localhost:8080 ; PORT=… to change
BREAKIT_DATA_DIR=./data pnpm start   # keep the log
docker build -f apps/break-it/Dockerfile -t zkif-break-it ../.. && docker run -p 8080:8080 zkif-break-it
```

Outside Docker, run `pnpm warm-crs` once first. It downloads Barretenberg's reference string into
`~/.bb-crs`, and needs the network to do it. The sandboxed engine never fetches anything: without
the reference string it fails to start.

## Tests

`pnpm test` (about 15 s, real proofs and real processes):

| Suite | Covers |
|---|---|
| `ledger.test.ts` | Opens at exactly 10,000 fake USDC; payments decrement by exactly their amount and credit the recipient; overdraft, zero, negative and non-bigint amounts are refused without changing anything; top-up; bounded history |
| `oracle.test.ts` | The break detector accepts in-policy payments and flags each kind of violation |
| `engine.test.ts` | Real proofs against the real verifier and registry: legitimate payments debit exactly; the lookalike, another chain, over the limit, zero, an extra argument, an ungranted scope and an unlisted tool are blocked by name with the ledger untouched; the circuit refuses on its own with the precheck off; lockouts are per visitor; no proof, a moved, tampered, replayed or re-timed proof, an unknown commitment and a garbled envelope are rejected by name; forged passkey approvals and a second enrolment are refused; a verifier-accepted out-of-policy payment is reported as a break (anti-stub) |
| `attempt-log.test.ts` | Records exactly what it is given; counts by verdict, route and check; filters and pages; leaderboard order; persistence and reload, torn lines, size cap |
| `limits.test.ts` | Token buckets, gates, client addresses (spoof-resistant `X-Forwarded-For`), pseudonyms, handles, configuration |
| `service.test.ts` | The deployed shape over HTTP: the notice on every response, the sandbox self-check, CSP and static paths, API guards, accurate logging of executed, blocked and rejected attempts, 429s not logged, no addresses in the log file, reload after restart |
| `egress.test.ts` | No outbound-network code in the sources or pages |

## Known limits

- One instance, in-memory state: a restart is a new policy and a fresh ledger (the log persists).
- The owner is a software key that exists only during boot. A hardware passkey cannot be used, and
  revocation by the owner is impossible; the policy simply expires or the instance is redeployed.
- If someone does revoke the policy, the instance stops paying until it is redeployed. That would be
  a break, and the page and log show it.
- The 64 outstanding approval nonces of the registry are shared: someone requesting many challenges
  can briefly stop others from getting one (rate limits bound this).
- Handles are unverified.
