# Proof-of-Intent circuit specification

| | |
|---|---|
| Circuit | `proof_of_intent` (`packages/zk-circuit/crates/proof_of_intent`) |
| Spec version | 1 (policy schema version `POLICY_VERSION = 1`, domain tags `*.v1`) |
| Status | Phase 1 complete. Not audited. |
| Proof system | UltraHonk over BN254 (Barretenberg), zero-knowledge flavour |
| Hash | Poseidon2 sponge over the BN254 scalar field |

This document is the contract between the circuit and everything built on it. Sections 4 and 5
are normative: a TypeScript implementation that follows them must reproduce
`packages/zk-circuit/fixtures/vectors.json` exactly.

## 1. Purpose

An AI agent that calls tools over MCP cannot tell a human's instruction from text injected into
its inputs. API keys and OAuth tokens do not help, because they are all-or-nothing.

This circuit lets a human approve a **policy** once and bind it to a public **commitment**. Before
a sensitive tool call executes, a prover shows in zero knowledge that the call obeys the policy.
The party that executes the call learns that it is allowed and nothing else about the policy.

## 2. Roles and trust model

| Role | Who | Knows | Must not learn |
|---|---|---|---|
| Policy owner | A human, approving with a passkey | The whole policy | |
| Prover | The firewall middleware, or the hosted proving API | The whole policy and the action | |
| Verifier | The tool server, a payment gateway, or the audit log | The policy commitment and the action it is about to execute | The limit, the rest of the allowlist, the other scopes, the expiry, the salt |
| Agent | The LLM | The action it wants | The policy opening |

Three points shape the design:

1. **The proof hides the policy, not the action.** The verifier executes the call, so it already
   sees the tool, the amount and the recipient.
2. **Prover and verifier are different parties.** The public inputs are exactly what a verifier
   can rebuild from its own state: a commitment it registered earlier, its own clock, and the call
   in front of it.
3. **The circuit cannot know the time.** The timestamp is a public input. The verifier is
   responsible for checking that it is fresh.

## 3. The statement

The prover convinces the verifier that it knows a policy opening and a Merkle witness such that,
for the public values `policy_commitment`, `current_timestamp` and `action_binding`:

1. **The commitment opens.** `policy_commitment` is the commitment to the private policy.
2. **The recipient is allowlisted.** The action's recipient is a leaf of the Merkle tree whose
   root is the policy's `allowlist_root`.
3. **The amount is within bounds.** `0 < amount <= max_amount`.
4. **The scope is granted.** Bit `scope_index` of the policy's `scope_mask` is set.
5. **The policy has not expired.** `current_timestamp < expiry`.
6. **The proof is bound to one action.** `action_binding` is the binding hash of the exact action
   (`tool_id`, `scope_index`, `amount`, `recipient`, `nonce`) that satisfied points 2 to 4.

## 4. Interface

### 4.1 Public inputs

In this exact order. A proof has exactly three public inputs and no return value.

| # | Name | Noir type | Meaning | Where the verifier gets it |
|---|---|---|---|---|
| 0 | `policy_commitment` | `Field` | Commitment to the approved policy (section 5.5) | Its registry of commitments approved by passkey |
| 1 | `current_timestamp` | `u64` | Unix time in seconds, UTC | Its own clock, or a prover-supplied value it has checked for freshness |
| 2 | `action_binding` | `Field` | Binding hash of the action (section 5.7) | Recomputed from the call it is about to execute |

On the wire each public input is one field element: 32 bytes, big-endian. Barretenberg's
`public_inputs` file for this circuit is those three values concatenated, 96 bytes.

**The verifier must build all three values itself.** A verifier that accepts `action_binding` from
the prover has verified nothing about the call it is executing.

### 4.2 Private inputs

In ABI order. Struct fields are listed in declaration order.

| Name | Noir type | Range | Meaning |
|---|---|---|---|
| `policy.max_amount` | `u128` | `[0, 2^128)` | Largest amount allowed for a single action, in base units |
| `policy.allowlist_root` | `Field` | `[0, p)` | Root of the recipient allowlist tree (section 5.6) |
| `policy.scope_mask` | `u64` | `[0, 2^64)` | Bit `i` set means scope `i` is granted |
| `policy.expiry` | `u64` | `[0, 2^64)` | Unix seconds. The policy is valid strictly before this instant |
| `policy.salt` | `Field` | `[1, p)` | High-entropy blinding value. Zero is rejected |
| `action.tool_id` | `Field` | `[0, p)` | Identifier of the tool being called |
| `action.scope_index` | `u8` | `[0, 64)` | The scope this tool requires |
| `action.amount` | `u128` | `[1, 2^128)` | Amount of this action, in base units. Zero is rejected |
| `action.recipient` | `Field` | `[0, p)` | Identifier of the destination |
| `action.nonce` | `Field` | `[0, p)` | Unique per call. Also blinds the binding |
| `leaf_index` | `u32` | `[0, 2^20)` | Position of the recipient's leaf in the tree |
| `merkle_path` | `[Field; 20]` | `[0, p)` each | Sibling hashes, from the leaf level up |

The action fields are private inputs of the circuit even though the verifier knows them. They
reach the verifier's side of the statement through `action_binding`.

### 4.3 Input file shape

`Prover.toml` for `nargo execute` (and the equivalent nested object for `noir_js`):

```toml
policy_commitment = "0x…"
current_timestamp = "1794441600"
action_binding = "0x…"
leaf_index = "3"
merkle_path = ["0x…", "…20 entries…"]

[policy]
max_amount = "500000000"
allowlist_root = "0x…"
scope_mask = "131081"
expiry = "1798761600"
salt = "0x…"

[action]
tool_id = "0x…"
scope_index = "3"
amount = "125000000"
recipient = "0x…"
nonce = "0x…"
```

Pass integers as decimal strings and field elements as `0x` hex strings. Do not pass JavaScript
numbers: `u128` and `u64` values do not fit in a double.

## 5. Cryptographic definitions

### 5.1 Field

All hashing is over the BN254 scalar field:

```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
```

A field element is canonical when it is in `[0, p)`. Encoders must reject values `>= p`. They must
never reduce them silently.

### 5.2 Integers as field elements

An integer of type `u8`, `u32`, `u64` or `u128` enters a hash as the field element with the same
numeric value. No packing, no byte reordering.

### 5.3 The hash `H`

`H` is the Poseidon2 sponge used by Barretenberg and Noir: state width 4, rate 3, capacity 1, with
the input length mixed into the capacity element.

```
H(x[0], …, x[n-1]):                       n >= 1, each x[i] in [0, p)
    s = [0, 0, 0, n * 2^64]
    for each full block of three inputs (a, b, c), in order:
        s[0] += a;  s[1] += b;  s[2] += c
        s = P(s)
    r = n mod 3
    if r != 0:
        add the last r inputs to s[0], …, s[r-1]
        s = P(s)
    return s[0]
```

All additions are in the field. `P` is the Poseidon2 permutation over BN254 with state width 4
(S-box `x^5`, 8 full rounds, 56 partial rounds) with Barretenberg's constants. In the circuit it
is the `poseidon2_permutation` black-box function of the Noir standard library. The sponge is
`Poseidon2::hash(input, input.len())` from `noir-lang/poseidon` v0.4.0. `H` costs `ceil(n / 3)`
permutations.

Because the length `n` is in the initial state, inputs of different lengths never collide by
construction, even before the domain tag is considered.

Known answers, all produced by the pinned Noir code:

| Input | `H` |
|---|---|
| `[1000]` | `0x16433a80e26a23547e25d61dd95fd5793d1ca2dcd78ae64cd146d3b99a35fa7c` |
| `[1000, 2000]` | `0x118d5a5ecb25dafe99eb45cb196604a23d0b7c0cbd0c2be29e0787e59b7a1d8a` |
| `[1000, 2000, 3000]` | `0x0f1badcd0d52ced816fb6e6826fdf66ada038135d53cbb993f320ca6529223cd` |

`P([0, 1, 2, 3])[0] = 0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737`.
More vectors are in `fixtures/vectors.json` under `poseidon2`.

TypeScript implementations with byte-identical output (section 10.1 records how this was checked):

| Package | Call |
|---|---|
| `@aztec/bb.js` | `(await BarretenbergSync.initSingleton()).poseidon2Hash({ inputs })`, where each input is a 32-byte big-endian `Uint8Array`, returns `{ hash }` |
| `@zkpassport/poseidon2` | `poseidon2Hash(inputs: bigint[]): bigint` |

### 5.4 Domain tags

Every hash in the protocol starts with a tag. A tag is the ASCII string read as a big-endian
integer. In TypeScript: `BigInt("0x" + Buffer.from(label, "ascii").toString("hex"))`.

| Constant | ASCII label | Value |
|---|---|---|
| `TAG_POLICY_COMMITMENT` | `zkif.policy.commitment.v1` | `0x7a6b69662e706f6c6963792e636f6d6d69746d656e742e7631` |
| `TAG_ALLOWLIST_LEAF` | `zkif.allowlist.leaf.v1` | `0x7a6b69662e616c6c6f776c6973742e6c6561662e7631` |
| `TAG_ALLOWLIST_NODE` | `zkif.allowlist.node.v1` | `0x7a6b69662e616c6c6f776c6973742e6e6f64652e7631` |
| `TAG_ACTION_BINDING` | `zkif.action.binding.v1` | `0x7a6b69662e616374696f6e2e62696e64696e672e7631` |

Other constants:

| Constant | Value | Meaning |
|---|---|---|
| `POLICY_VERSION` | `1` | Version of the policy schema, hashed into every commitment |
| `TREE_DEPTH` | `20` | Levels between a leaf and the root |
| `MAX_LEAVES` | `1048576` | `2^TREE_DEPTH` |
| `SCOPE_BITS` | `64` | Width of `scope_mask` |
| `EMPTY_LEAF` | `0` | Value of an unoccupied leaf position |

### 5.5 Policy commitment

```
policy_commitment = H( TAG_POLICY_COMMITMENT,
                       POLICY_VERSION,
                       max_amount,
                       allowlist_root,
                       scope_mask,
                       expiry,
                       salt )
```

Seven inputs, three permutations. `salt` must be drawn uniformly from a cryptographic random
source. A good way is 31 random bytes read as a big-endian integer. Never reuse a salt across
policies and never derive it from the policy.

### 5.6 Recipient allowlist tree

A binary Merkle tree of fixed depth 20. Leaves are at height 0, the root is at height 20.

```
leaf(recipient)   = H( TAG_ALLOWLIST_LEAF, recipient )         two inputs, one permutation
node(left, right) = H( TAG_ALLOWLIST_NODE, left, right )       three inputs, one permutation
```

- An occupied position holds `leaf(recipient)`. An unoccupied position holds `EMPTY_LEAF = 0`.
  That is the field element zero, not the hash of anything.
- The value of a node at height `h + 1` is `node(left child, right child)`.
- An empty subtree of height `h` has the value `Z[h]`, where `Z[0] = 0` and
  `Z[h + 1] = node(Z[h], Z[h])`. The root of an empty allowlist is `Z[20]`. All 21 values are in
  the fixtures under `zero_hashes`.

Leaf and node hashes differ in both tag and input length, so a node can never be presented as a
leaf. No recipient can open an empty position, because that would need a preimage of zero.

**Merkle path.** For the leaf at position `i`, `merkle_path[h]` is the value of the sibling of the
path node at height `h`, for `h = 0 … 19`. The circuit recomputes the root as:

```
cur = leaf(recipient)
for h in 0 … 19:
    bit = (leaf_index >> h) & 1            # 0: cur is a left child, 1: cur is a right child
    cur = bit == 0 ? node(cur, merkle_path[h]) : node(merkle_path[h], cur)
root = cur
```

**Placement.** The circuit accepts any placement of recipients. For reproducible roots, Phase 2
should place the distinct recipients at positions `0 … n-1` in ascending order of their field
value. The fixture uses insertion order, to make sure nothing depends on sorted input.

### 5.7 Action binding

```
action_binding = H( TAG_ACTION_BINDING,
                    tool_id,
                    scope_index,
                    amount,
                    recipient,
                    nonce )
```

Six inputs, two permutations.

## 6. Constraints

Every assertion of the circuit is in `crates/proof_of_intent/src/main.nr`. The library crate
computes and never asserts.

| ID | Constraint | Assertion message |
|---|---|---|
| C1a | `policy.salt != 0` | `policy salt must be non-zero` |
| C1b | `H(TAG_POLICY_COMMITMENT, 1, policy…) == policy_commitment` | `policy commitment mismatch` |
| C2a | `leaf_index < 2^20` | `leaf index out of range` |
| C2b | recomputed root `== policy.allowlist_root` | `recipient not in allowlist` |
| C3a | `action.amount != 0` | `amount must be non-zero` |
| C3b | `action.amount <= policy.max_amount` | `amount exceeds policy limit` |
| C4a | `action.scope_index < 64` | `scope index out of range` |
| C4b | bit `action.scope_index` of `policy.scope_mask` is 1 | `scope not granted by policy` |
| C5 | `current_timestamp < policy.expiry` | `policy expired` |
| C6 | `H(TAG_ACTION_BINDING, action…) == action_binding` | `action binding mismatch` |

Constraints the compiler adds from the types, which the circuit relies on:

- Every integer parameter of `main` is range-constrained to its bit width (`u8`, `u32`, `u64`,
  `u128`). Section 11.3 records the check of the compiled ACIR.
- The comparisons in C2a, C3b, C4a and C5 are integer comparisons on range-constrained values. No
  comparison is ever made on a raw `Field`, so wraparound modulo `p` cannot occur.
- `leaf_index` and `scope_mask` are split into bits with `Field::to_le_bits`, which constrains
  every output to be boolean and the bits to recompose to the input. The Merkle direction bits are
  therefore boolean by construction.
- The scope bit is selected by comparing `scope_index` with each of the 64 positions. There is no
  array lookup and no memory operation anywhere in the circuit.

C2a and C4a are stated for clarity and for a precise error. The circuit would reject the same
inputs without them: an index of `2^20` or more has no 20-bit decomposition, and a scope index of
64 or more matches no position, so it reads as not granted.

## 7. Design decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Poseidon2**, as the standard library's `poseidon2_permutation` black box plus the sponge from `noir-lang/poseidon` v0.4.0. | nargo 1.0.0 ships no hash for field elements except this permutation, and its documentation points to that library for the sponge. Barretenberg proves the permutation with dedicated gates, so the whole circuit needs only 26 permutations. The same C++ code is exposed to TypeScript by `@aztec/bb.js`, which Phase 2 needs anyway for proving. Poseidon (the original) would need a pure-Noir permutation at many times the gate count. |
| D2 | **The action goes through a binding hash**, not through separate public inputs. | The public interface stays at three values however the action schema grows. A third party such as an audit log can verify a proof without seeing the action, because the nonce blinds the binding, and the action can be opened later by revealing the preimage. Collision resistance of `H` is already assumed for the commitment and the tree, so no new assumption is added. The cost is two permutations and one hash on the verifier side. |
| D3 | **`amount` and `max_amount` are `u128`.** | A token with 18 decimals overflows `u64` at about 18.4 units. `u128` holds 3.4 × 10^20 such units. |
| D4 | **Timestamps are `u64` Unix seconds.** | Matches every platform's time API and cannot overflow in practice. |
| D5 | **A zero amount is invalid.** | An integration bug that drops the amount would otherwise turn into a call that passes every limit. Zero-value transfers are also a known vector for address-poisoning. A tool with no natural quantity uses `amount = 1`. |
| D6 | **Tree depth is 20 and fixed.** | Room for 1,048,576 recipients at 20 permutations. A fixed depth means the proof reveals nothing about the size of the allowlist and removes the variable-depth ambiguity behind second-preimage attacks. |
| D7 | **Empty positions hold the constant 0.** | Unambiguous, cheap to build sparsely with the `Z[h]` table, and impossible to open as a recipient. |
| D8 | **`leaf_index` is one integer, split into bits inside the circuit.** | One value is harder to get wrong than twenty booleans, and the bit order is fixed by the circuit, not by the caller. |
| D9 | **Scopes are a 64-bit mask and each action names one required bit.** | Compact, constant cost, and no vacuous case: a mask-of-required-bits design would accept "no scope required". `scope_index` is part of the binding, so the verifier, which knows what its tool requires, is the one that fixes it. |
| D10 | **Replay protection is a nonce inside the binding.** | The proof is single-use once the verifier refuses a binding it has already seen. A separate public nullifier would add nothing here, because the verifier already knows the commitment and the action. Keeping the nonce out of the public inputs is also what lets it blind the binding. |
| D11 | **The passkey signature is verified off-circuit.** | The commitment is public, so nothing is gained by hiding the signature over it. A standard WebAuthn check on the verifier is simpler and far cheaper than P-256 and SHA-256 over WebAuthn data in a circuit, and it runs once per policy, not once per call. In-circuit verification would only be justified if the commitment itself had to stay hidden from the verifier, which this trust model rules out. |
| D12 | **The salt is mandatory and must be non-zero.** | Without a salt, a low-entropy policy could be found by brute force from the public commitment. The circuit cannot measure entropy, but rejecting zero stops an uninitialised salt from ever producing a proof. |
| D13 | **`POLICY_VERSION` is a circuit constant inside the commitment.** | A commitment made for one policy schema can never be opened under another. |
| D14 | **Tags are ASCII labels read as integers.** | Self-describing, unique to this protocol, and trivial to reproduce in any language. |
| D15 | **Expiry is strict: valid if and only if `current_timestamp < expiry`.** | `expiry` is the first instant at which the policy is no longer valid. |
| D16 | **Public values are inputs checked by assertion, not return values.** | The prover's hashing code and the circuit must agree before a proof exists, so an encoding bug in TypeScript fails loudly at witness generation with a named assertion. |
| D17 | **The scope bit is selected by comparison, not by an array lookup.** | With a lookup the compiler drops the explicit 8-bit range constraint on `scope_index`, because the lookup implies it. Comparing against every position keeps every integer input explicitly range-constrained, makes the check a total function, and removes memory operations from the circuit. It costs 127 gates, which changes nothing about the proving cost (section 11.3). |
| D18 | **Four crates.** `policy_primitives` (library) and `proof_of_intent` (binary) are the security path. `testkit` (library) and `fixture_gen` (binary) are off-circuit tooling. | The security path contains no `unconstrained` function and no `unsafe` block, and that is checked by a script. Every assertion sits in one file. |

## 8. Threat model

### 8.1 What is protected

1. **The resource behind the tool** (funds, data): an action outside the policy must not execute.
2. **The policy**: the verifier and anyone observing proofs must not learn it.

### 8.2 Adversaries

| Adversary | Goal | Outcome |
|---|---|---|
| Agent steered by prompt injection | Execute an action outside the policy | No valid proof exists for such an action, so an honest verifier refuses it. Actions inside the policy remain possible (section 9, L1). |
| Network observer | Replay a captured proof | The verifier refuses a binding it has seen, and refuses a stale timestamp. |
| Network observer | Reuse a proof for a different call | The binding fixes tool, scope, amount, recipient and nonce. |
| Curious verifier | Learn the limit, the allowlist, the scopes or the expiry | The proof is zero-knowledge and the commitment is hiding because of the salt. The verifier learns only that each accepted action was allowed. |
| Malicious verifier | Replay a proof at another verifier | Prevented when `tool_id` identifies the verifier as well as the tool (section 10.4), or when each verifier issues its own nonces. |
| Malicious prover | Forge a proof for an action outside the policy | Prevented by the soundness of the proof system. It cannot open the commitment to a different policy without a hash collision. |
| Reader of a third-party log | Learn the actions | It sees the commitment, the timestamp, the binding and the proof. With a nonce of at least 128 bits of entropy the binding reveals nothing about the action. |

### 8.3 Assumptions

- UltraHonk as implemented by Barretenberg is sound and, in its zero-knowledge flavour,
  zero-knowledge. This includes the BN254 structured reference string Barretenberg downloads.
- The Poseidon2 sponge is collision resistant and behaves as a random oracle for hiding.
- The verifier holds the authentic verification key of this circuit and the authentic commitment.
- The verifier checks freshness, replay and revocation as described in section 10.3.
- The prover keeps the policy opening away from the agent.

### 8.4 What the circuit does not claim

- It does not show that a human wanted this particular action. It shows that the action lies
  inside what a human approved.
- It does not hide the policy from the prover. Whoever runs the prover sees the policy.
- It does not limit how many actions are taken.

## 9. Known limitations

| # | Limitation | Who must handle it |
|---|---|---|
| L1 | **Per-action limit only.** An agent can make many actions that each pass. There is no cumulative budget, velocity limit or count limit. | The verifier or payment gateway, or the SaaS layer. A later circuit version could prove a running total against a committed state. |
| L2 | **No revocation.** A proof for a revoked policy still verifies until `expiry`. | The verifier must check that the commitment is still registered when it verifies. |
| L3 | **No proof of human approval in the circuit.** | Phase 2 verifies the passkey signature over the commitment off-circuit (D11). |
| L4 | **Replay tracking is outside the circuit.** | The verifier stores seen bindings for as long as it would accept their timestamp. |
| L5 | **One limit, one unit.** `max_amount` is a bare number. If an allowlist mixes assets with different units, the same number applies to all of them. | Phase 2 must make the recipient identifier commit to the asset and network (section 10.4) and should use one policy per asset. |
| L6 | **Exact-match allowlist.** There is no wildcard and no "any recipient" policy. | Tools without a recipient use an agreed resource identifier. |
| L7 | **One scope bit per action, 64 scopes.** | A shared registry that maps scope names to bit positions, owned by Phase 2. |
| L8 | **At most 1,048,576 allowlist entries.** | Raising `TREE_DEPTH` is a new circuit and a new verification key. |
| L9 | **The time is whatever the verifier accepts.** A verifier that accepts an old `current_timestamp` accepts an expired policy. | The verifier (section 10.3). |
| L10 | **Rejections leak.** Anyone who can make the prover attempt chosen actions and see whether a proof came back can search for the limit in about 128 attempts, and can test recipients for membership. | The firewall must rate-limit and must not expose its refusals to untrusted parties. |
| L11 | **Not audited.** Neither this circuit, nor `noir-lang/poseidon` (which calls itself experimental), nor this exact toolchain pairing has had an external audit. | Before protecting real funds. |
| L12 | **Tests run honest witness generation on hostile inputs.** They show that no input makes `main` accept a false statement. They cannot show that a prover who skips the witness generator is stopped. That rests on the compiler's constraints and on the absence of unconstrained code on the security path. | An audit. |
| L13 | **On-chain verification is not a target.** A contract would have to recompute a Poseidon2 binding. | A later version, if needed. |
| L14 | **No "not before" time.** A policy is valid from the moment it is registered. | The registry. |

## 10. Phase 2 integration notes

### 10.1 Packages and versions

| Purpose | Package | Notes |
|---|---|---|
| Witness generation | `@noir-lang/noir_js` 1.0.0 | Must match nargo 1.0.0, which compiled the circuit. |
| Proving and verifying | `@aztec/bb.js` 5.3.0, or the native `bb` 5.3.0 | Pinned. See the version note below. |
| `H` in TypeScript | `@aztec/bb.js`, or `@zkpassport/poseidon2` | Both checked against the fixtures in Phase 1. |

The hash was checked outside the repository on 2026-11-12: an independent JavaScript
implementation of sections 5.3 to 5.7 reproduced every value in `fixtures/vectors.json` with both
`@aztec/bb.js` 5.3.0 and `@zkpassport/poseidon2` 0.6.2.

**Version note.** The project pins Barretenberg 5.3.0: `@aztec/bb.js` 5.3.0 (npm `latest`) in
`packages/mcp-firewall`, and native `bb` 5.3.0 (`bbup -v 5.3.0`) as the matching CLI. Checked on
2026-11-13:

- The verification keys of 5.3.0 and 6.0.0 are byte-identical, so `fixtures/vk_hashes.txt` holds
  for both.
- Proofs do not cross-verify between the 5.3.0 and 6.0.0 lines, in either direction
  (`UltraVerifier: verification failed at reduction step`). Every prover and verifier must run
  5.3.0.
- bb.js 5.3.0 and native `bb` 5.3.0 verify each other's proofs on both targets.
  `pnpm firewall:check:bbjs` repeats the round trip and the cross-check.

History: Phase 1 used `bb` 6.0.0, bbup's default pairing for nargo 1.0.0, which has no stable
bb.js release on npm.

### 10.2 Prover flow

1. Load the policy opening from storage the agent cannot reach.
2. Map the intercepted tool call to an `Action`. Draw a fresh `nonce`, or take the one the
   verifier issued.
3. Find the recipient's position, build its Merkle path, and compute `policy_commitment` and
   `action_binding` in TypeScript.
4. Generate the witness with `noir_js`. A named assertion failure here means the call is outside
   the policy or the TypeScript encoding disagrees with the circuit.
5. Prove with a zero-knowledge verifier target (section 10.5).
6. Send the call, the proof, `current_timestamp` and `nonce` to the verifier. Never send the
   policy.

### 10.3 Verifier checklist

A verifier must do all of the following. Each one is a way the system fails if skipped.

1. Look up `policy_commitment` in its own registry. Confirm that it was approved by a valid
   passkey signature and that it has not been revoked.
2. Take `current_timestamp` from its own clock, or check that the supplied value is within a small
   window of its clock (30 to 60 seconds is reasonable).
3. Derive `tool_id`, `scope_index`, `amount` and `recipient` from the call it is about to execute
   and from its own configuration. Take only `nonce` from the request.
4. Recompute `action_binding` (section 5.7).
5. Refuse if `(policy_commitment, action_binding)` has been seen before. Keep each entry for as
   long as its timestamp would still be accepted. Deduplicate on the binding, never on the proof
   bytes.
6. Verify the proof against the pinned verification key with the public inputs
   `[policy_commitment, current_timestamp, action_binding]`.
7. Execute exactly the call that was bound. Enforce any cumulative limit separately (L1).

### 10.4 Identifiers

The circuit treats `tool_id`, `recipient` and `nonce` as opaque field elements. Phase 2 owns their
encoding. The circuit's guarantees depend on three properties:

- **`tool_id` must be unique across verifiers.** It should commit to the identity of the tool
  server as well as the tool name. Otherwise a proof made for one server can be replayed at
  another that trusts the same commitment.
- **`recipient` must commit to everything that decides where value goes and in what unit**: the
  network, the asset and the account. Otherwise a limit meant as 500 units of one asset also
  authorises 500 base units of any other asset sent to the same account.
- **`nonce` must be unique per call**, and must have at least 128 bits of entropy if the action
  should stay hidden from parties that see only the public inputs.

Recommended encoding, used for the fixture constants. It needs only SHA-256 and always yields a
canonical field element:

```
to_field(domain, part_1, …, part_k) =
    the first 31 bytes of SHA-256( domain || 0x0A || part_1 || 0x0A || … || part_k ),
    read as a big-endian integer

tool_id   = to_field("zkif.tool.v1", server_id, tool_name)
recipient = to_field("zkif.recipient.v1", asset_id, account_id)       CAIP-19 and CAIP-10 strings
nonce     = 31 random bytes read as a big-endian integer
```

Parts are UTF-8 and must not contain a line feed (`0x0A`).

### 10.5 Proving target and keys

- **Always use a zero-knowledge target.** In `bb` 5.3.0, the version this project pins, the default
  target is zero-knowledge. `noir-recursive` (Poseidon2 transcript, the default) and `evm` (Keccak
  transcript, a proof about half the size) were both exercised in Phase 1. The `*-no-zk` targets
  leak information about the witness, which here is the policy. Never use them.
- The verification key depends on the circuit and on the target. Generate it once with
  `bb write_vk`, publish its hash, and have verifiers pin it. A different key means a different
  circuit. `fixtures/vk_hashes.txt` records the hashes for this circuit under nargo 1.0.0 and
  `bb` 5.3.0; they are confirmed identical under `bb` 6.0.0. `pnpm --filter
  @zk-intent-firewall/zk-circuit run prove` fails if they change.
- The passkey approval should sign more than the bare commitment: include the hash of the
  verification key and a label for this protocol, so that an approval cannot be reinterpreted
  under another circuit.

### 10.6 Using the fixtures

`packages/zk-circuit/fixtures/` holds two files generated by the Noir code:

- `Prover.toml`: a complete valid input. `pnpm circuit:execute` runs the circuit on it.
- `vectors.json`: constants, hash vectors, the zero-hash table, the allowlist with every leaf,
  root and Merkle path, the policy and its commitment, the action and its binding, the public
  inputs in order, and edge cases at the top of every integer range and at `p - 1`.

Phase 2's first test should recompute every value in `vectors.json` from its inputs.

A third file, `vk_hashes.txt`, is written by Barretenberg, not by Noir. It records the hash of
the verification key for each proving target.

The scenario behind the fixtures: a policy that allows at most 500 units of a six-decimal token
(`max_amount = 500000000`) to five recipients, under scopes 0, 3 and 17, until
2027-01-01T00:00:00Z. The action pays 125 units to the recipient at position 3 under scope 3, at
2026-11-12T00:00:00Z. The identifiers follow section 10.4 with the asset
`eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`, the accounts `eip155:1:0x1111…1111`
to `eip155:1:0x5555…5555`, the server `https://payments.example.com/mcp` and the tool
`send_payment`. The salt and nonce are `to_field("zkif.fixture.v1", "policy-salt")` and
`to_field("zkif.fixture.v1", "nonce-0001")`. They are public test data.

## 11. Toolchain and reproducibility

### 11.1 Pinned versions

| Component | Version | Pinned by |
|---|---|---|
| nargo / noirc | 1.0.0 (commit `275d3ab1a5c916c6ea73e8d6b943f685f574500c`) | `compiler_version = "=1.0.0"` in every `Nargo.toml` |
| Barretenberg `bb` | 5.3.0 | `bbup -v 5.3.0`. Matches `@aztec/bb.js` 5.3.0, pinned exactly in `packages/mcp-firewall` (section 10.1). Phase 1 originally used 6.0.0 |
| `noir-lang/poseidon` | tag `v0.4.0`, commit `e105cdd5c79c222860d53c5dfdb8fa8012b291c0` | `tag` in `Nargo.toml`, and `scripts/check-deps.sh` compares the fetched commit |
| Node.js | 26.13.1 | `.nvmrc`, `engines` |
| pnpm | 12.18.0 | `packageManager`, `engines` |

nargo has no lockfile and a git tag can be moved. `scripts/check-deps.sh` therefore checks that
the commit nargo fetched for `v0.4.0` is the one recorded above. The known-answer tests would also
fail if the hash changed.

### 11.2 Nothing unconstrained on the security path

`crates/policy_primitives` and `crates/proof_of_intent/src/main.nr` contain no `unconstrained`
function and no `unsafe` block. `scripts/check-security-path.sh` enforces this. The only
unconstrained code that runs inside the circuit is generated by the compiler (hints for bit
decomposition, integer quotient and field inversion), and the compiler constrains its results.

The upstream sponge has a separate branch for unconstrained execution. The circuit uses the
constrained branch. `testkit` and `fixture_gen` run the unconstrained branch, and the known-answer
tests check that both agree on the fixture's commitment, binding, leaves, root and zero hashes.

### 11.3 Evidence

Recorded on 2026-11-12 on a 12th Gen Intel Core i5-12400F (12 threads) under WSL2. The prove and
verify figures were re-recorded on 2026-11-13 with `bb` 5.3.0 on the same machine; every other
`bb` figure (gates, sizes, key hashes) is identical under 5.3.0 and 6.0.0.

**Tests.** `pnpm test` runs `nargo test --workspace --deny-warnings`: 152 tests, all passing.

| Package | Tests | What they cover |
|---|---|---|
| `proof_of_intent` | 105 | 75 rejections, each naming the assertion that must fire; 19 acceptances including every boundary; 9 known answers; 2 checks of test helpers |
| `policy_primitives` | 32 | Hash vectors, tags, sponge definition, Merkle direction and bit order, commitment and binding field by field, scope bits |
| `testkit` | 15 | The reference tree builder against the circuit's Merkle code |

Every rejection test is a constrained function that calls `main` on witnesses, so the constraints
run as they do when a proof is made.

**Mutation check.** `scripts/mutation-check.sh` removes each assertion in turn, then applies 38
other changes to the security path (off-by-one bounds, truncated comparisons, inverted Merkle
direction, wrong bit order, swapped or missing hash inputs, wrong tags). All 48 mutants are
killed. The assertion removals:

| Removed assertion | Result | Failing tests |
|---|---|---|
| `policy salt must be non-zero` | killed | 1 |
| `policy commitment mismatch` | killed | 17 |
| `leaf index out of range` | killed | 3 |
| `recipient not in allowlist` | killed | 13 |
| `amount must be non-zero` | killed | 2 |
| `amount exceeds policy limit` | killed | 9 |
| `scope index out of range` | killed | 3 |
| `scope not granted by policy` | killed | 7 |
| `policy expired` | killed | 8 |
| `action binding mismatch` | killed | 12 |

For `leaf index out of range` and `scope index out of range` the tests fail because the named
assertion no longer fires. The inputs are still rejected by the bit decomposition and by
`scope not granted by policy`, as section 6 explains.

**Compiled circuit.** `nargo compile --print-acir` was read in full:

- An explicit range opcode on each of the seven integer inputs: `current_timestamp` 64 bits,
  `max_amount` 128, `scope_mask` 64, `expiry` 64, `scope_index` 8, `amount` 128, `leaf_index` 32.
- 84 one-bit range opcodes: 20 Merkle direction bits and 64 scope bits, each set followed by the
  equation that recomposes the input.
- 26 `POSEIDON2_PERMUTATION` opcodes, with initial states `7 * 2^64`, `2 * 2^64`, `3 * 2^64` and
  `6 * 2^64` for the commitment, the leaf, the nodes and the binding.
- No memory opcode.
- Three compiler-generated hints (`directive_invert`, `directive_integer_quotient`,
  `directive_to_radix`), each followed by the constraints that check its result.
- Twelve named assertions: the ten of section 6 and the two bit decompositions.

nargo's checks for under-constrained values and for unconstrained Brillig results are on by
default and are never disabled.

**Size.** `nargo info`: 562 ACIR opcodes. `bb gates`: 5,237 gates.

| Part | Gates |
|---|---|
| Fixed cost of the first range check wider than 8 bits | about 2,750 |
| 26 Poseidon2 permutations at 73 gates | 1,898 |
| Everything else: bit decompositions, Merkle selects, comparisons, scope selection | about 590 |

The prover pads to the next power of two, 8,192. The circuit has about 2,950 gates of headroom
before proving cost doubles, and it cannot drop to 4,096 while it has any wide range check, so
there is nothing to gain from trading clarity for gates here.

**Prove and verify.** `scripts/prove-verify.sh` with `bb` 5.3.0, median of the whole `bb` process
per run; the ranges span three runs (one of five samples, two of nine), with the prove ranges
widened for run-to-run variance after a later run measured 248 ms (`noir-recursive`) and 174 ms
(`evm`):

| Target | Prove | Verify | Proof | Verification key |
|---|---|---|---|---|
| `noir-recursive` (Poseidon2 transcript, zero-knowledge) | 230–250 ms | 9–10 ms | 14,656 bytes | 3,680 bytes |
| `evm` (Keccak transcript, zero-knowledge) | 165–180 ms | 7 ms | 7,616 bytes | 1,888 bytes |

History: Phase 1 measured `bb` 6.0.0 at 135 ms and 109 ms to prove, 10 ms and 7 ms to verify.

For both targets the public inputs of the proof are the three fixture values in order, and
verification fails when any one of them, or the proof, is changed by one bit.

**Input boundary.** `nargo execute` refuses an input file with `amount = 2^128`,
`current_timestamp = 2^64`, `expiry = 2^64`, `scope_index = 256`, `leaf_index = 2^32`, or a field
element equal to `p`, before any witness is generated.

**Cross-implementation.** A JavaScript implementation written from sections 5.3 to 5.7 and 10.4,
kept outside the repository, recomputed every value in `fixtures/vectors.json` and
`fixtures/Prover.toml` with three implementations of `H`: `@aztec/bb.js` 5.3.0,
`@zkpassport/poseidon2` 0.6.2, and the sponge of section 5.3 written out over the bb.js
permutation. 572 comparisons, no mismatch.
