#!/usr/bin/env bash
# Mutation check for the proof-of-intent circuit.
#
# Part 1 removes every assertion of the circuit, one at a time.
# Part 2 applies a list of small semantic changes to the security path, one at a time.
#
# After each change the whole test suite runs. A mutant is KILLED when at least one test fails.
# A mutant that SURVIVES means a constraint can be weakened without any test noticing: that is a
# missing test, and this script exits with an error.
#
# The source file is restored after every mutant, and on exit, including on Ctrl-C.
# The report is printed as a Markdown table and written to target/mutation-report.md.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

main_file="crates/proof_of_intent/src/main.nr"
lib_dir="crates/policy_primitives/src"

work="$(mktemp -d)"
current_file=""
restore() {
  if [[ -n "$current_file" && -f "$work/backup.nr" ]]; then
    cp "$work/backup.nr" "$current_file"
  fi
  current_file=""
}
cleanup() {
  restore
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

rows=()
survivors=0
broken=0
number=0

# Runs the whole suite. Leaves the plain-text output in $work/out.txt and returns nargo's status.
run_suite() {
  local status=0
  nargo test --workspace --silence-warnings > "$work/raw.txt" 2>&1 || status=$?
  sed -E 's/\x1b\[[0-9;]*m//g' "$work/raw.txt" > "$work/out.txt"
  return "$status"
}

# Names of the tests that failed in the last run, one per line.
failed_tests() {
  grep -E '^\[[^]]+\] Testing .* \.\.\. FAIL' "$work/out.txt" \
    | sed -E 's/^\[[^]]+\] Testing (.*) \.\.\. FAIL.*$/\1/' || true
}

# Applies one mutation to one file, runs the suite, records the result and restores the file.
#   $1 file   $2 description   $3... arguments for sed -i
mutate() {
  local file="$1" description="$2"
  shift 2
  number=$((number + 1))
  local id
  id="$(printf 'M%02d' "$number")"

  cp "$file" "$work/backup.nr"
  current_file="$file"
  sed -i -E "$@" "$file"
  if cmp -s "$file" "$work/backup.nr"; then
    restore
    echo "$id: the mutation did not change $file: $description" >&2
    exit 1
  fi

  local status=0
  run_suite || status=$?
  restore

  local failed count example result
  failed="$(failed_tests)"
  count="$(printf '%s' "$failed" | grep -c . || true)"
  example="$(printf '%s\n' "$failed" | head -n 1)"
  if [[ "$count" -gt 0 ]]; then
    result="killed"
  elif [[ "$status" -ne 0 ]]; then
    result="BROKEN"
    broken=$((broken + 1))
    example="the mutant did not compile"
    echo "$id: mutant did not compile. Output:" >&2
    tail -n 25 "$work/out.txt" >&2
  else
    result="SURVIVED"
    survivors=$((survivors + 1))
    example="none"
  fi

  rows+=("| $id | \`${file##*/}\` | $description | $result | $count | \`$example\` |")
  printf '%s  %-8s  %3s failing  %s\n' "$id" "$result" "$count" "$description" >&2
}

echo "baseline: running the unmodified suite" >&2
if ! run_suite; then
  echo "the unmodified test suite does not pass, so a mutation check is meaningless" >&2
  tail -n 25 "$work/out.txt" >&2
  exit 1
fi
baseline="$(grep -E 'tests? passed' "$work/out.txt" | sed -E 's/^\[([^]]+)\] ([0-9]+) tests? passed.*$/\1 \2/' | tr '\n' ';')"
echo "baseline: all tests pass ($baseline)" >&2

# ---------------------------------------------------------------------------------------------
# Part 1: remove every assertion of the circuit.
# ---------------------------------------------------------------------------------------------
mapfile -t assertion_lines < <(sed -E 's://.*$::' "$main_file" | grep -nE '^[[:space:]]*assert\(' | cut -d: -f1)
if [[ "${#assertion_lines[@]}" -eq 0 ]]; then
  echo "found no assertion in $main_file" >&2
  exit 1
fi
# The library must hold none, or this part would miss some.
if sed -E 's://.*$::' "$lib_dir"/{lib,constants,hash,merkle,policy,action}.nr | grep -qE '\bassert(_eq|_ne)?[[:space:]]*\('; then
  echo "found an assertion in $lib_dir: extend this script to cover it" >&2
  exit 1
fi

for line in "${assertion_lines[@]}"; do
  text="$(sed -n "${line}p" "$main_file")"
  if [[ ! "$text" =~ \)\;[[:space:]]*$ ]]; then
    echo "the assertion at $main_file:$line spans several lines: keep it on one line" >&2
    exit 1
  fi
  message="$(grep -oE '"[^"]*"' <<< "$text" | tail -n 1 | tr -d '"')"
  mutate "$main_file" "remove assertion \"$message\" (line $line)" \
    "${line}s|^([[:space:]]*)assert\(.*$|\1// mutant: assertion removed|"
done
assertions="${#assertion_lines[@]}"

# ---------------------------------------------------------------------------------------------
# Part 2: weaken or distort the security path in other ways.
# ---------------------------------------------------------------------------------------------

# Boundaries and wiring in main.nr.
mutate "$main_file" "amount limit becomes exclusive: \`<=\` to \`<\`" \
  's/assert\(action\.amount <= policy\.max_amount/assert(action.amount < policy.max_amount/'
mutate "$main_file" "expiry becomes inclusive: \`<\` to \`<=\`" \
  's/assert\(current_timestamp < policy\.expiry/assert(current_timestamp <= policy.expiry/'
mutate "$main_file" "leaf index bound off by one: \`<\` to \`<=\`" \
  's/assert\(leaf_index < MAX_LEAVES/assert(leaf_index <= MAX_LEAVES/'
mutate "$main_file" "scope index bound off by one: \`<\` to \`<=\`" \
  's/as u32\) < SCOPE_BITS/as u32) <= SCOPE_BITS/'
mutate "$main_file" "amount compared on its low 64 bits only" \
  's/assert\(action\.amount <= policy\.max_amount/assert((action.amount as u64) <= (policy.max_amount as u64)/'
mutate "$main_file" "timestamp compared on its low 32 bits only" \
  's/assert\(current_timestamp < policy\.expiry/assert((current_timestamp as u32) < (policy.expiry as u32)/'
mutate "$main_file" "leaf is the recipient itself, not its hash" \
  's/compute_root\(hash_leaf\(action\.recipient\), /compute_root(action.recipient, /'
mutate "$main_file" "commitment checked against the wrong public input" \
  's/policy\.commitment\(\) == policy_commitment/policy.commitment() == action_binding/'

# Merkle path.
mutate "$lib_dir/merkle.nr" "Merkle direction bit inverted" \
  's/if is_right_child\[height\] \{/if !is_right_child[height] {/'
mutate "$lib_dir/merkle.nr" "Merkle direction bit ignored: node always on the left" \
  's/\(sibling, node\)/(node, sibling)/'
mutate "$lib_dir/merkle.nr" "leaf index bits read most significant first" \
  's/\(leaf_index as Field\)\.to_le_bits\(\)/(leaf_index as Field).to_be_bits()/'

# Hashes.
mutate "$lib_dir/hash.nr" "leaf hashed with the node tag" \
  's/poseidon2\(\[TAG_ALLOWLIST_LEAF, recipient\]\)/poseidon2([TAG_ALLOWLIST_NODE, recipient])/'
mutate "$lib_dir/hash.nr" "node hashed with the leaf tag" \
  's/poseidon2\(\[TAG_ALLOWLIST_NODE, left, right\]\)/poseidon2([TAG_ALLOWLIST_LEAF, left, right])/'
mutate "$lib_dir/hash.nr" "node hashed without a tag" \
  's/poseidon2\(\[TAG_ALLOWLIST_NODE, left, right\]\)/poseidon2([left, right])/'
mutate "$lib_dir/hash.nr" "node children hashed in swapped order" \
  's/poseidon2\(\[TAG_ALLOWLIST_NODE, left, right\]\)/poseidon2([TAG_ALLOWLIST_NODE, right, left])/'
mutate "$lib_dir/hash.nr" "sponge ignores its last input" \
  's/Poseidon2::hash\(input, N\)/Poseidon2::hash(input, N - 1)/'

# Policy commitment.
mutate "$lib_dir/policy.nr" "commitment tag replaced by 1" \
  's/^([[:space:]]*)TAG_POLICY_COMMITMENT,$/\11,/'
mutate "$lib_dir/policy.nr" "commitment without the policy version" \
  '/^[[:space:]]*POLICY_VERSION,$/d'
mutate "$lib_dir/policy.nr" "commitment without max_amount" \
  '/^[[:space:]]*self\.max_amount as Field,$/d'
mutate "$lib_dir/policy.nr" "commitment without allowlist_root" \
  '/^[[:space:]]*self\.allowlist_root,$/d'
mutate "$lib_dir/policy.nr" "commitment without scope_mask" \
  '/^[[:space:]]*self\.scope_mask as Field,$/d'
mutate "$lib_dir/policy.nr" "commitment without expiry" \
  '/^[[:space:]]*self\.expiry as Field,$/d'
mutate "$lib_dir/policy.nr" "commitment without the salt" \
  '/^[[:space:]]*self\.salt,$/d'
mutate "$lib_dir/policy.nr" "commitment with scope_mask and expiry swapped" \
  's/self\.scope_mask as Field,/@@,/; s/self\.expiry as Field,/self.scope_mask as Field,/; s/@@,/self.expiry as Field,/'
mutate "$lib_dir/policy.nr" "commitment keeps only the low 64 bits of max_amount" \
  's/self\.max_amount as Field,/(self.max_amount as u64) as Field,/'

# Scope mask.
mutate "$lib_dir/policy.nr" "scope mask read most significant bit first" \
  's/\(self\.scope_mask as Field\)\.to_le_bits\(\)/(self.scope_mask as Field).to_be_bits()/'
mutate "$lib_dir/policy.nr" "scope check reads the neighbouring bit" \
  's/\(scope_index as u32 == bit\)/(scope_index as u32 == bit + 1)/'
mutate "$lib_dir/policy.nr" "scope check ignores the mask" \
  's/granted\[bit\] & \(scope_index as u32 == bit\)/(scope_index as u32 == bit)/'
mutate "$lib_dir/policy.nr" "scope check ignores the index" \
  's/granted\[bit\] & \(scope_index as u32 == bit\)/granted[bit]/'
mutate "$lib_dir/policy.nr" "scope check starts from yes" \
  's/let mut result = false;/let mut result = true;/'

# Action binding.
mutate "$lib_dir/action.nr" "binding tag replaced by 1" \
  's/^([[:space:]]*)TAG_ACTION_BINDING,$/\11,/'
mutate "$lib_dir/action.nr" "binding without tool_id" \
  '/^[[:space:]]*self\.tool_id,$/d'
mutate "$lib_dir/action.nr" "binding without scope_index" \
  '/^[[:space:]]*self\.scope_index as Field,$/d'
mutate "$lib_dir/action.nr" "binding without amount" \
  '/^[[:space:]]*self\.amount as Field,$/d'
mutate "$lib_dir/action.nr" "binding without recipient" \
  '/^[[:space:]]*self\.recipient,$/d'
mutate "$lib_dir/action.nr" "binding without the nonce" \
  '/^[[:space:]]*self\.nonce,$/d'
mutate "$lib_dir/action.nr" "binding with tool_id and recipient swapped" \
  's/self\.tool_id,/@@,/; s/self\.recipient,/self.tool_id,/; s/@@,/self.recipient,/'
mutate "$lib_dir/action.nr" "binding keeps only the low 64 bits of amount" \
  's/self\.amount as Field,/(self.amount as u64) as Field,/'

# ---------------------------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------------------------
echo "final: running the restored suite" >&2
if ! run_suite; then
  echo "the suite fails after restoring the sources: inspect the working tree" >&2
  exit 1
fi

mkdir -p target
{
  echo "| # | File | Mutation | Result | Failing tests | First failing test |"
  echo "|---|---|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
  echo
  echo "Mutants: $number ($assertions assertion removals, $((number - assertions)) other changes). Killed: $((number - survivors - broken)). Survived: $survivors. Did not compile: $broken."
} | tee target/mutation-report.md

if [[ "$survivors" -ne 0 || "$broken" -ne 0 ]]; then
  echo "mutation check FAILED" >&2
  exit 1
fi
echo "mutation check passed: every mutant was killed" >&2
