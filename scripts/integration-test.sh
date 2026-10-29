#!/usr/bin/env bash
# Runs the Go integration tests against a local validator started in WSL.
# Run from Git Bash on Windows (Go runs on Windows, the validator in WSL).
# Requires `make anchor-build` first.
set -euo pipefail
export MSYS_NO_PATHCONV=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WSL_ROOT="$(wsl -e wslpath -a "$(cygpath -w "$ROOT")" | tr -d '\r')"
RPC_URL="http://127.0.0.1:8899"
LOG="$ROOT/.local/validator.log"
mkdir -p "$ROOT/.local"

PROGRAM_ID="$(wsl -e bash "$WSL_ROOT/scripts/localnet.sh" program-id | tr -d '\r')"

# Generates the test keypair on first run, then holds the validator in the
# foreground of this background job.
wsl -e bash "$WSL_ROOT/scripts/localnet.sh" run >"$LOG" 2>&1 &
VALIDATOR=$!
cleanup() {
	kill "$VALIDATOR" 2>/dev/null || true
	wsl -e pkill -f solana-test-validator 2>/dev/null || true
}
trap cleanup EXIT

echo "waiting for validator..."
for _ in $(seq 1 90); do
	if curl -s -X POST -H 'Content-Type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" | grep -q '"ok"'; then
		ready=1
		break
	fi
	if ! kill -0 "$VALIDATOR" 2>/dev/null; then
		echo "validator exited; log:" >&2
		cat "$LOG" >&2
		exit 1
	fi
	sleep 1
done
[ "${ready:-}" = 1 ] || { echo "validator did not become healthy; log:" >&2; cat "$LOG" >&2; exit 1; }

cd "$ROOT"
# Default to every package; -p 1 runs packages one at a time since they share
# one validator.
if [ "$#" -eq 0 ]; then set -- ./internal/... ./cmd/...; fi
CREDENTIAL_TEST_RPC_URL="$RPC_URL" \
CREDENTIAL_TEST_PROGRAM_ID="$PROGRAM_ID" \
CREDENTIAL_TEST_AUTHORITY_KEYPAIR="$(cygpath -m "$ROOT/.local/test-authority-keypair.json")" \
	go test -tags integration -count=1 -p 1 "$@"
