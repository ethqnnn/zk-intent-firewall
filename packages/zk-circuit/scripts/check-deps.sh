#!/usr/bin/env bash
# Checks the pin of every external Noir dependency.
#
# nargo pins a git dependency by tag and has no lockfile, and a git tag can be moved. This script
# checks that the commit nargo fetched for the tag is the commit that was reviewed.
#
# Run it after any nargo command that fetches dependencies, for example `nargo test`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The only external dependency: repository, tag, reviewed commit.
dep_repo="github.com/noir-lang/poseidon"
dep_tag="v0.4.0"
dep_commit="e105cdd5c79c222860d53c5dfdb8fa8012b291c0"

# nargo stores git dependencies under ~/nargo/<host>/<owner>/<repo>/<tag>.
cache_root="${NARGO_GIT_CACHE:-$HOME/nargo}"

fail() {
  echo "check-deps: $*" >&2
  exit 1
}

# 1. The manifests declare exactly this one git dependency, at this tag.
mapfile -t git_deps < <(grep -rhE '^[[:space:]]*[A-Za-z0-9_-]+[[:space:]]*=.*\bgit[[:space:]]*=' --include=Nargo.toml . || true)
if [[ "${#git_deps[@]}" -ne 1 ]]; then
  fail "expected exactly one git dependency in the Nargo.toml files, found ${#git_deps[@]}"
fi
if [[ "${git_deps[0]}" != *"https://$dep_repo"* || "${git_deps[0]}" != *"tag = \"$dep_tag\""* ]]; then
  fail "unexpected git dependency: ${git_deps[0]}"
fi

# 2. The commit nargo fetched for that tag is the reviewed one.
dep_dir="$cache_root/$dep_repo/$dep_tag"
if [[ ! -d "$dep_dir/.git" ]]; then
  fail "$dep_dir not found. Run 'nargo test' once so nargo fetches it, or set NARGO_GIT_CACHE."
fi
fetched="$(git -C "$dep_dir" rev-parse HEAD)"
if [[ "$fetched" != "$dep_commit" ]]; then
  fail "$dep_repo tag $dep_tag resolved to $fetched, expected $dep_commit. The tag has moved."
fi

# 3. The fetched tree has not been edited locally.
if [[ -n "$(git -C "$dep_dir" status --porcelain)" ]]; then
  fail "$dep_dir has local modifications"
fi

echo "$dep_repo $dep_tag is at the reviewed commit $dep_commit"
