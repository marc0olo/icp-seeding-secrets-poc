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
diff -q /tmp/vectors-check.json motoko/bls12-381/test/vectors.json \
  || { echo "motoko/bls12-381/test/vectors.json is stale"; exit 1; }

step "motoko: check and test"
( cd motoko/bls12-381 && mops check src/*.mo >/dev/null && mops test )

step "typescript: typecheck, tests, diagrams"
( cd seed && npm run --silent typecheck && npm test && npm run --silent check:diagrams )

printf '\n\033[1mall checks passed\033[0m\n'
