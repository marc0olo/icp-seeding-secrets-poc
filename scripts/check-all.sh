#!/usr/bin/env bash
#
# Everything CI runs, minus the replica round trip. Run this before pushing.
#
# It exists because this repo has three toolchains — cargo, mops and node — and
# working in one makes it easy to forget the others. Two CI failures came from
# exactly that: a `cargo fmt` miss and a clippy lint, both while mid-way through
# Motoko work.

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

step "vectors match the reference"
cargo run -q -p vectorgen > /tmp/vectors-check.json
diff -q /tmp/vectors-check.json motoko/test/vectors.json \
  || { echo "motoko/test/vectors.json is stale"; exit 1; }

step "motoko: check and test"
( cd motoko && mops check src/*.mo >/dev/null && mops test )

step "typescript: typecheck, tests, diagrams"
( cd seed && npm run --silent typecheck && npm test && npm run --silent check:diagrams )

printf '\n\033[1mall checks passed\033[0m\n'
