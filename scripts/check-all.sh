#!/usr/bin/env bash
#
# Everything CI runs, minus the replica round trip. Run this before pushing.
#
# It exists because this repo has three toolchains — cargo, mops and node — and
# working in one makes it easy to forget the others. Two CI failures came from
# exactly that: a `cargo fmt` miss and a clippy lint, both while mid-way through
# Motoko work. A third came from the generated `.did` and TypeScript bindings
# going stale, which is why they are regenerated and diffed here rather than
# only in CI.

set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "rust: format"
cargo fmt --all --check

step "rust: clippy"
cargo clippy --workspace --all-targets -- -D warnings

step "rust: tests"
cargo test --workspace --quiet

step "rust: canister builds both ways"
cargo build -p sealed-secrets-canister --target wasm32-unknown-unknown --release --locked
cargo build -p sealed-secrets-canister --target wasm32-unknown-unknown --release --locked --features test-hooks

step "generated bindings are up to date"
# Deliberately after the test-hooks build above: that is the wasm CI extracts
# from, and the two feature sets produce different Candid.
command -v candid-extractor >/dev/null \
  || { echo "candid-extractor not installed: cargo install candid-extractor"; exit 1; }
# Compare against the content as it was *before* regenerating, not against
# HEAD: the question is "does regeneration change anything", and a git-status
# check would also fire on unrelated uncommitted edits to these same files.
before=$(mktemp -d)
cp -R rust/canister/sealed_secrets_canister.did seed/src/declarations "$before/"
candid-extractor target/wasm32-unknown-unknown/release/sealed_secrets_canister.wasm \
  > rust/canister/sealed_secrets_canister.did
npm --prefix seed run --silent bindings >/dev/null
if ! diff -r -q "$before/sealed_secrets_canister.did" rust/canister/sealed_secrets_canister.did \
  || ! diff -r -q "$before/declarations" seed/src/declarations; then
  echo "the .did or seed/src/declarations was stale — regenerated above, review and commit"
  rm -rf "$before"
  exit 1
fi
rm -rf "$before"

step "vectors match the reference"
cargo run -q -p vectorgen > /tmp/vectors-check.json
diff -q /tmp/vectors-check.json motoko/vectors.json \
  || { echo "motoko/vectors.json is stale"; exit 1; }

step "motoko: check and test"
# Warnings fail here on purpose. The M0236/M0237/M0223 lints are enabled in each
# package's mops.toml and `mops check --fix` applies them, so a warning means
# someone skipped the auto-fix — and `mops check` itself exits 0 on warnings, so
# nothing else would catch it.
for pkg in bls12-381 vetkeys canister; do
  (
    cd "motoko/$pkg"
    out=$(mops check src/*.mo 2>&1) || { echo "$out"; exit 1; }
    if echo "$out" | grep -q "warning"; then
      echo "$out" | grep "warning"
      echo "moc warnings in motoko/$pkg — run 'mops check --fix' there"
      exit 1
    fi
    mops test
  )
done

step "typescript: typecheck, tests, diagrams"
( cd seed && npm run --silent typecheck && npm test && npm run --silent check:diagrams )

printf '\n\033[1mall checks passed\033[0m\n'
