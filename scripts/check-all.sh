#!/usr/bin/env bash
#
# Everything CI runs except the replica round trip. Run this before pushing.
#
# The repo has three toolchains — cargo, mops and node — and working in one
# makes it easy to forget the others.

set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "rust: format, lint, build"
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p dummy-secret-canister --target wasm32-unknown-unknown --release --locked

step "the committed .did matches the canister"
candid-extractor target/wasm32-unknown-unknown/release/dummy_secret_canister.wasm > /tmp/extracted.did
diff -q /tmp/extracted.did rust/canister/dummy_secret.did \
  || { echo "rust/canister/dummy_secret.did is stale"; exit 1; }

step "motoko: the vectors still match the Rust reference"
cargo run -q -p vectorgen > /tmp/vectors.json
diff -q /tmp/vectors.json motoko/vectors.json \
  || { echo "motoko/vectors.json is stale"; exit 1; }

step "motoko: check and test"
# Warnings fail on purpose: the M0236/M0237/M0223 lints are enabled in each
# mops.toml and `mops check --fix` applies them, but `mops check` exits 0 on
# warnings, so nothing else would catch a regression.
for pkg in bls12-381 vetkeys canister; do
  (
    cd "motoko/$pkg"
    out=$(mops check src/*.mo 2>&1) || { echo "$out"; exit 1; }
    if echo "$out" | grep -q "warning"; then
      echo "$out" | grep "warning"
      echo "moc warnings in motoko/$pkg — run 'mops check --fix' there"
      exit 1
    fi
    # Only the two libraries have tests; the canisters are covered end to end.
    [ "$pkg" = canister ] || mops test
  )
done

step "typescript: typecheck"
( cd seed && npm run --silent typecheck )

printf '\n\033[1mall checks passed\033[0m\n'
