#!/usr/bin/env bash
# Generates the fixtures from the Noir code, or checks that the committed ones are current.
#
#   scripts/fixtures.sh write    regenerate fixtures/Prover.toml and fixtures/vectors.json
#   scripts/fixtures.sh check    fail if the committed fixtures differ from what the code prints
#
# The fixture files are printed by crates/fixture_gen between BEGIN and END marker lines.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mode="${1:-check}"
if [[ "$mode" != "write" && "$mode" != "check" ]]; then
  echo "usage: scripts/fixtures.sh [write|check]" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

nargo execute --package fixture_gen --deny-warnings > "$work/raw.txt"

extract() {
  local name="$1"
  awk -v begin="=== BEGIN $name ===" -v end="=== END $name ===" '
    $0 == end { inside = 0; closed = 1 }
    inside { print }
    $0 == begin { inside = 1 }
    END { if (!closed) exit 1 }
  ' "$work/raw.txt" > "$work/$name" || {
    echo "fixture_gen did not print a complete $name" >&2
    exit 1
  }
  if [[ ! -s "$work/$name" ]]; then
    echo "fixture_gen printed an empty $name" >&2
    exit 1
  fi
}

extract Prover.toml
extract vectors.json

# vectors.json is assembled line by line, so make sure it parses.
if command -v node > /dev/null 2>&1; then
  node -e 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"))' "$work/vectors.json"
else
  echo "note: node is not on PATH, so vectors.json was not parsed" >&2
fi

if [[ "$mode" == "write" ]]; then
  mkdir -p fixtures
  cp "$work/Prover.toml" fixtures/Prover.toml
  cp "$work/vectors.json" fixtures/vectors.json
  echo "wrote fixtures/Prover.toml and fixtures/vectors.json"
else
  diff -u fixtures/Prover.toml "$work/Prover.toml"
  diff -u fixtures/vectors.json "$work/vectors.json"
  echo "fixtures are up to date with the Noir code"
fi
