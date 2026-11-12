#!/usr/bin/env bash
# Real prove and verify round trip on the fixture, with Barretenberg.
#
#   scripts/prove-verify.sh [target ...]      default targets: noir-recursive evm
#
# For each verifier target it:
#   1. writes the verification key and compares its hash with fixtures/vk_hashes.txt,
#   2. proves the fixture witness and verifies the proof,
#   3. checks that the public inputs are the three fixture values in order,
#   4. checks that verification FAILS when any public input or the proof is changed,
#   5. reports the median prove and verify time over RUNS runs (default 5).
#
# Set UPDATE_VK_HASHES=1 to record new verification key hashes after a deliberate circuit or
# toolchain change. A changed hash means a different circuit: every verifier must be updated.
#
# Both default targets are zero-knowledge. Never use a "-no-zk" target for this circuit: a proof
# that is not zero-knowledge leaks information about the policy.
set -euo pipefail
shopt -s inherit_errexit
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v bb > /dev/null 2>&1; then
  echo "bb is not on PATH: skipping the prove and verify round trip"
  exit 0
fi

runs="${RUNS:-5}"
vk_hash_file="fixtures/vk_hashes.txt"
targets=("$@")
if [[ "${#targets[@]}" -eq 0 ]]; then
  targets=(noir-recursive evm)
fi
for target in "${targets[@]}"; do
  if [[ "$target" == *no-zk* ]]; then
    echo "refusing target '$target': it is not zero-knowledge" >&2
    exit 2
  fi
done

hex_of() { od -An -v -tx1 "$1" | tr -d ' \n'; }

# Flips the lowest bit of the byte at an offset of a file.
flip_bit() {
  local file="$1" offset="$2" byte
  byte="$(od -An -v -tx1 -j "$offset" -N 1 "$file" | tr -d ' \n')"
  printf "$(printf '\\x%02x' "$((0x$byte ^ 1))")" | dd of="$file" bs=1 seek="$offset" conv=notrunc status=none
}

# Succeeds when bb rejects the proof.
rejects() {
  ! bb verify -k "$1" -p "$2" -i "$3" -t "$4" > /dev/null 2>&1
}

# Median wall-clock time of a command in milliseconds over $runs runs. The median drops the
# outliers that a clock adjustment (common under WSL) would otherwise put into the result.
median_ms() {
  local samples=() start end
  for _ in $(seq "$runs"); do
    start="$(date +%s%N)"
    "$@" > /dev/null 2>&1
    end="$(date +%s%N)"
    samples+=("$(((end - start) / 1000000))")
  done
  printf '%s\n' "${samples[@]}" | sort -n | sed -n "$(((runs + 1) / 2))p"
}

recorded_vk_hash() {
  awk -v target="$1" '$1 == target { print $2 }' "$vk_hash_file" 2> /dev/null || true
}

echo "nargo: $(nargo --version | head -n 1 | sed 's/^nargo version = //')"
echo "bb:    $(bb --version)"

nargo compile --package proof_of_intent --deny-warnings > /dev/null
nargo execute --package proof_of_intent --prover-name ../../fixtures/Prover > /dev/null
bytecode="target/proof_of_intent.json"
witness="target/proof_of_intent.gz"

# The three public inputs of the fixture, in order, as 64 hex digits each.
expected_inputs="$(awk '
  /"public_inputs": \[/ { inside = 1; next }
  inside && /\]/ { exit }
  inside { gsub(/[ ",]/, ""); sub(/^0x/, ""); printf "%s", $0 }
' fixtures/vectors.json)"
if [[ "${#expected_inputs}" -ne 192 ]]; then
  echo "could not read the three public inputs from fixtures/vectors.json" >&2
  exit 1
fi

gates="$(bb gates -b "$bytecode" 2> /dev/null | grep -oE '"circuit_size": *[0-9]+' | grep -oE '[0-9]+$')"
opcodes="$(bb gates -b "$bytecode" 2> /dev/null | grep -oE '"acir_opcodes": *[0-9]+' | grep -oE '[0-9]+$')"
echo "circuit: $opcodes ACIR opcodes, $gates gates"
echo

summary=()
new_hashes=()
hash_mismatch=0
for target in "${targets[@]}"; do
  out="target/bb/$target"
  rm -rf "$out"
  mkdir -p "$out"

  # 1. Verification key.
  bb write_vk -b "$bytecode" -o "$out" -t "$target" > "$out/write_vk.log" 2>&1
  vk_hash="0x$(hex_of "$out/vk_hash")"
  new_hashes+=("$target $vk_hash")
  recorded="$(recorded_vk_hash "$target")"
  if [[ "${UPDATE_VK_HASHES:-0}" != "1" && "$recorded" != "$vk_hash" ]]; then
    echo "$target: verification key hash is $vk_hash, but $vk_hash_file records '${recorded:-nothing}'" >&2
    hash_mismatch=1
  fi

  # 2. Prove and verify.
  bb prove -b "$bytecode" -w "$witness" -k "$out/vk" -o "$out" -t "$target" > "$out/prove.log" 2>&1
  bb verify -k "$out/vk" -p "$out/proof" -i "$out/public_inputs" -t "$target" > "$out/verify.log" 2>&1

  # 3. The public inputs are the fixture values, in order.
  if [[ "$(hex_of "$out/public_inputs")" != "$expected_inputs" ]]; then
    echo "$target: the public inputs of the proof are not the fixture values in order" >&2
    exit 1
  fi

  # 4. Changing any public input, or the proof, must make verification fail.
  names=(policy_commitment current_timestamp action_binding)
  for i in 0 1 2; do
    cp "$out/public_inputs" "$out/public_inputs.tampered"
    flip_bit "$out/public_inputs.tampered" "$((i * 32 + 31))"
    if ! rejects "$out/vk" "$out/proof" "$out/public_inputs.tampered" "$target"; then
      echo "$target: a proof verified with a changed ${names[$i]}" >&2
      exit 1
    fi
  done
  cp "$out/proof" "$out/proof.tampered"
  flip_bit "$out/proof.tampered" "$(($(stat -c %s "$out/proof") / 2))"
  if ! rejects "$out/vk" "$out/proof.tampered" "$out/public_inputs" "$target"; then
    echo "$target: a changed proof verified" >&2
    exit 1
  fi
  rm -f "$out/public_inputs.tampered" "$out/proof.tampered"

  # 5. Timing.
  prove_ms="$(median_ms bb prove -b "$bytecode" -w "$witness" -k "$out/vk" -o "$out" -t "$target")"
  verify_ms="$(median_ms bb verify -k "$out/vk" -p "$out/proof" -i "$out/public_inputs" -t "$target")"

  proof_bytes="$(stat -c %s "$out/proof")"
  vk_bytes="$(stat -c %s "$out/vk")"
  summary+=("| \`$target\` | $prove_ms ms | $verify_ms ms | $proof_bytes bytes | $vk_bytes bytes | \`$vk_hash\` |")
  echo "$target: proof verifies, 3 changed public inputs and 1 changed proof are rejected"
done

if [[ "${UPDATE_VK_HASHES:-0}" == "1" ]]; then
  {
    echo "# Verification key hashes of the proof_of_intent circuit, one line per verifier target."
    echo "# Written by scripts/prove-verify.sh with nargo $(nargo --version | head -n 1 | sed 's/^nargo version = //') and bb $(bb --version)."
    echo "# A different hash means a different circuit, and every verifier must be updated."
    printf '%s\n' "${new_hashes[@]}"
  } > "$vk_hash_file"
  echo "recorded the verification key hashes in $vk_hash_file"
elif [[ "$hash_mismatch" -ne 0 ]]; then
  echo "The circuit or the toolchain changed. If that was intended, run with UPDATE_VK_HASHES=1." >&2
  exit 1
fi

echo
echo "| Target | Prove | Verify | Proof | Verification key | Verification key hash |"
echo "|---|---|---|---|---|---|"
printf '%s\n' "${summary[@]}"
echo
echo "Times are the median of $runs runs of the whole bb process on $(nproc) threads, including"
echo "start-up and loading the reference string."
