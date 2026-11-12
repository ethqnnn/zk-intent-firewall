#!/usr/bin/env bash
# Checks the structural rules of the security path.
#
# The security path is the code that ends up in the circuit:
#   crates/policy_primitives/src/*.nr   except tests.nr
#   crates/proof_of_intent/src/main.nr
#
# Rules:
#   1. No `unconstrained` function and no `unsafe` block anywhere on the security path.
#   2. The library only computes. Every assertion is in main.nr, where the mutation check finds it.
#   3. main.nr does not use the test kit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

main_file="crates/proof_of_intent/src/main.nr"
mapfile -t lib_files < <(find crates/policy_primitives/src -name '*.nr' ! -name 'tests.nr' | sort)
if [[ "${#lib_files[@]}" -eq 0 ]]; then
  echo "check-security-path: no library files found" >&2
  exit 1
fi

status=0

# Prints "file:line:code" for every line whose code, with comments removed, matches the pattern.
code_matches() {
  local pattern="$1"
  shift
  local file
  for file in "$@"; do
    sed -E 's://.*$::' "$file" | grep -nE "$pattern" | sed "s|^|$file:|" || true
  done
}

report() {
  local rule="$1" found="$2"
  if [[ -n "$found" ]]; then
    echo "FAIL  $rule" >&2
    echo "$found" | sed 's/^/        /' >&2
    status=1
  else
    echo "ok    $rule"
  fi
}

report "no unconstrained function or unsafe block on the security path" \
  "$(code_matches '\b(unconstrained|unsafe)\b' "${lib_files[@]}" "$main_file")"

report "no assertion outside main.nr" \
  "$(code_matches '\b(assert|assert_eq|assert_ne|static_assert|assert_constant)[[:space:]]*\(' "${lib_files[@]}")"

report "main.nr does not use the test kit" \
  "$(code_matches '\btestkit\b' "$main_file")"

assertions="$(code_matches '^[[:space:]]*assert\(' "$main_file" | wc -l | tr -d ' ')"
echo "      $main_file holds $assertions assertions"

exit "$status"
