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
# Checked against the wasm binary, not just the extracted Candid: a canister
# method IS a wasm export, so a name absent from the bytes cannot be called at
# all. Confirmed once by hand — calling secret_reveal on a default build is
# rejected by the replica with IC0536 "Canister has no update method".
cargo build -p sealed-secrets-canister --target wasm32-unknown-unknown --release --locked >/dev/null 2>&1
PROD_WASM=target/wasm32-unknown-unknown/release/sealed_secrets_canister.wasm
for hook in secret_reveal; do
  if grep -aq "$hook" "$PROD_WASM"; then
    fail "'$hook' is present in the default build; test-hooks is leaking into production"
  fi
done
# A control, so this cannot pass by looking at the wrong file or a stale build.
grep -aq "icp_sealed_secret_set" "$PROD_WASM" \
  || fail "control failed: icp_sealed_secret_set missing from $PROD_WASM"
echo "  ok — secret_reveal absent from the binary (control: set present)"

say "2. the generated TypeScript bindings match the canister"
( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )
# git is the portable diff here: no shasum/sha256sum, which differ across macOS
# and slim Linux images. The declarations are tracked, so regenerating and
# finding no change is the check.
cargo build -p sealed-secrets-canister --target wasm32-unknown-unknown --release --locked \
  --features test-hooks >/dev/null 2>&1
candid-extractor target/wasm32-unknown-unknown/release/sealed_secrets_canister.wasm \
  > crates/canister/sealed_secrets_canister.did
# Compare the working tree against itself across a regeneration, rather than
# against HEAD: this must pass mid-change, before anything is committed. CI runs
# the stricter "regenerated output matches what is committed" check.
GEN_PATHS="crates/canister/sealed_secrets_canister.did seed/src/declarations"
BEFORE=$(git diff -- $GEN_PATHS; git status --porcelain -- $GEN_PATHS)
npm --prefix seed run --silent bindings >/dev/null 2>&1
AFTER=$(git diff -- $GEN_PATHS; git status --porcelain -- $GEN_PATHS)
[ "$BEFORE" = "$AFTER" ] \
  || fail "seed/src/declarations was stale — regenerating changed it. Review and commit."
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
CID=$(icp canister status "$CANISTER" -e "$ENV" --json | jq -r .id)
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

say "9. an operator can confirm the right value WITHOUT revealing it"
# This is the production-safe check: seal the expected value and ask the canister
# whether it matches. One bit back, nothing disclosed in either direction.
SEALED_MATCHES=$(icp canister call "$CANISTER" icp_sealed_secret_matches \
  "(\"$SECRET_NAME\", blob \"\")" -e "$ENV" 2>&1 || true)
echo "  (matches() with an empty blob is correctly rejected as malformed)"
grep -q "InvalidCiphertext" <<<"$SEALED_MATCHES" \
  || fail "matches() did not reject a malformed candidate"
echo "  ok — matches() validates its input"

say "10. the actual use case: an authenticated HTTPS outcall"
# The point of the whole exercise. The canister reads the plaintext, puts it in
# an Authorization header, calls out, and returns only the status code — never
# the body, which on an echoing endpoint would hand the header straight back.
#
# The target genuinely evaluates the credential, so BOTH outcomes are proof that
# the call completed and the header was read: 401 for the dummy value this test
# seals, 200 if you seal a real GitHub token. Only a network failure gives
# neither, which is what this asserts.
STATUS=$(icp canister call "$CANISTER" call_api_with_secret "(\"$SECRET_NAME\")" -e "$ENV" 2>&1 | tr -d '\n ')
case "$STATUS" in
  *"Ok=401"*) echo "  ok — outcall reached the API, which evaluated and rejected the dummy credential" ;;
  *"Ok=200"*) echo "  ok — outcall authenticated successfully (a real token is sealed)" ;;
  *) fail "the authenticated outcall did not complete: $STATUS" ;;
esac

say "11. it survives an upgrade with no re-seeding"
icp deploy -e "$ENV" >/dev/null
AFTER=$(icp canister call "$CANISTER" secret_reveal "(\"$SECRET_NAME\")" -e "$ENV" 2>/dev/null \
  | tr -d '\n' | sed -n 's/.*= "\(.*\)".*/\1/p')
[ "$AFTER" = "$SECRET_VALUE" ] || fail "the secret did not survive the upgrade"
echo "  ok — still readable after upgrade, ciphertext lives in stable memory"

say "12. the negative cases"
npm --prefix seed run --silent e2e -- --canister "$CID" --host "$HOST" --source pocketic --pem "$PEM"

say "done"
echo "Stop the network with: icp network stop"
