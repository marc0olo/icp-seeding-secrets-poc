#!/usr/bin/env bash
#
# Seal a secret for a canister and send it.
#
#   DUMMY_API_KEY=sk-... ./scripts/seal.sh sealed-secrets-rust DUMMY_API_KEY
#   DUMMY_API_KEY=sk-... ./scripts/seal.sh sealed-secrets-rust DUMMY_API_KEY ic
#
# Two steps behind one command, and they are worth knowing apart:
#
#   1. seed/src/index.ts encrypts. It needs no identity and touches no network —
#      deriving this canister's public key and encrypting to it is pure
#      computation, doable before the canister has run an instruction.
#   2. `icp canister call` sends it, signed. That step needs a controller of the
#      canister — any identity that controls it, from any client. This uses
#      icp-cli because it already holds one, which is why nothing is exported.
#
# The value is read from an environment variable named after the secret, never
# from argv: argv is world-readable via `ps` and is echoed into CI logs.
#
# Run the two by hand if you would rather watch each one; the README shows how.
# Check the subnet first, once per deployment:
#
#   npm --prefix seed run preflight -- --canister <id> --host <url>

set -euo pipefail
cd "$(dirname "$0")/.."

CANISTER=${1:-}
NAME=${2:-}
ENV=${3:-local}
if [ -z "$CANISTER" ] || [ -z "$NAME" ] || [ -z "${!NAME:-}" ]; then
  echo "usage: <NAME>=<value> $0 <canister-name> <NAME> [environment]" >&2
  echo "       e.g. DUMMY_API_KEY=sk-... $0 sealed-secrets-rust DUMMY_API_KEY" >&2
  exit 1
fi

# Which master-key table to derive from. Not guessable from the key name —
# mainnet and a local network both have a key_1, backed by different keys.
SOURCE=pocketic
[ "$ENV" = ic ] && SOURCE=mainnet

# One method name for both canisters. That is the point of the interface being a
# proposed standard rather than a per-language convention.
METHOD=icp_sealed_secret_set

ARG=$(mktemp)
trap 'rm -f "$ARG"' EXIT

( cd seed && [ -d node_modules ] || npm install --silent >/dev/null 2>&1 )

CID=$(icp canister status "$CANISTER" -e "$ENV" -i)
npm --prefix seed run --silent seal -- \
  --canister "$CID" --source "$SOURCE" --name "$NAME" --out "$ARG"
icp canister call "$CANISTER" "$METHOD" --args-file "$ARG" -e "$ENV"
