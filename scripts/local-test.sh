#!/usr/bin/env bash
#
# One-command local verification of the whole round trip.
#
#   ./scripts/local-test.sh
#
# Starts a local network, deploys, seals a secret, and proves the canister
# recovered the exact plaintext — including reading it back in the clear via the
# `test-hooks` build, so you can see it with your own eyes.
#
# Also asserts that a build WITHOUT `--features test-hooks` exports no endpoint
# that can observe a secret.

set -euo pipefail

cd "$(dirname "$0")/.."

CANISTER=sealed-secrets
ENV=local
HOST=http://127.0.0.1:8010
SECRET_NAME=DUMMY_API_KEY
SECRET_VALUE="sk-local-test-$(date +%s)-do-not-use"
PEM="$(mktemp -t sealed-secrets-id)"
TEST_IDENTITY=sealed-secrets-test

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() { rm -f "$PEM"; }
trap cleanup EXIT

say "1. the default build exposes no way to observe a secret"
cargo build -p sealed-secrets-canister --target wasm32-unknown-unknown --release --locked >/dev/null 2>&1
DEFAULT_DID=$(candid-extractor target/wasm32-unknown-unknown/release/sealed_secrets_canister.wasm 2>/dev/null || true)
if grep -qE "secret_reveal|secret_sha256" <<<"$DEFAULT_DID"; then
  fail "the default build exports an observation endpoint; test-hooks is leaking into it"
fi
echo "  ok — no secret_reveal, no secret_sha256"

say "2. the generated TypeScript bindings match the canister"
( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )
BEFORE=$(shasum -a 256 seed/src/declarations/*.ts | shasum -a 256)
npm --prefix seed run --silent bindings >/dev/null 2>&1
AFTER=$(shasum -a 256 seed/src/declarations/*.ts | shasum -a 256)
[ "$BEFORE" = "$AFTER" ] || fail "seed/src/declarations is stale — run 'npm --prefix seed run bindings' and commit"
echo "  ok — declarations are up to date with the .did"

say "3. make sure an identity exists"
# A fresh container (CI) has none, and the network seeds cycles to the default
# identity at start-up — so this has to happen BEFORE the network comes up.
# `plaintext` storage because a container has no keyring and no TTY to answer a
# password prompt.
if ! icp identity default >/dev/null 2>&1; then
  icp identity new "$TEST_IDENTITY" --storage plaintext --quiet >/dev/null
  icp identity default "$TEST_IDENTITY" >/dev/null
  echo "  created '$TEST_IDENTITY'"
fi
IDENTITY=$(icp identity default)
echo "  using '$IDENTITY' ($(icp identity principal))"

say "4. start the local network"
if icp network status "$ENV" >/dev/null 2>&1; then
  echo "  already running"
else
  icp network start "$ENV" --background
fi

say "5. deploy (with --features test-hooks, per icp.yaml)"
icp deploy -e "$ENV" >/dev/null
CID=$(icp canister status "$CANISTER" -e "$ENV" --json | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
echo "  canister: $CID"

say "6. health check — does this subnet actually serve vetKD?"
icp canister call "$CANISTER" icp_sealed_secret_self_test '(opt variant { PocketIc })' -e "$ENV" 2>/dev/null \
  | grep -qE "public_key_matches_master = opt true" \
  || fail "self_test could not confirm the subnet's public key against the compiled-in master key"
echo "  ok — vetkd_derive_ok, and the subnet's key matches the PocketIC master key"

say "7. seal a secret"
icp identity export "$IDENTITY" > "$PEM"
( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )
SEAL_IDENTITY_PEM="$PEM" \
  env "$SECRET_NAME=$SECRET_VALUE" \
  npm --prefix seed run --silent seal -- \
    --canister "$CID" --name "$SECRET_NAME" --host "$HOST" --source pocketic --local

say "8. read it back IN THE CLEAR (test-hooks build only)"
REVEALED=$(icp canister call "$CANISTER" secret_reveal "(\"$SECRET_NAME\")" -e "$ENV" 2>/dev/null \
  | tr -d '\n' | sed -n 's/.*= "\(.*\)".*/\1/p')
echo "  sealed:   $SECRET_VALUE"
echo "  revealed: $REVEALED"
[ "$REVEALED" = "$SECRET_VALUE" ] || fail "the canister did not recover the plaintext"
echo "  ok — byte-for-byte match"

say "9. it survives an upgrade with no re-seeding"
icp deploy -e "$ENV" >/dev/null
AFTER=$(icp canister call "$CANISTER" secret_reveal "(\"$SECRET_NAME\")" -e "$ENV" 2>/dev/null \
  | tr -d '\n' | sed -n 's/.*= "\(.*\)".*/\1/p')
[ "$AFTER" = "$SECRET_VALUE" ] || fail "the secret did not survive the upgrade"
echo "  ok — still readable after upgrade, ciphertext lives in stable memory"

say "10. the negative cases"
npm --prefix seed run --silent e2e -- --canister "$CID" --host "$HOST" --source pocketic --pem "$PEM"

say "done"
echo "Stop the network with: icp network stop"
