# Sourced by scripts that need a local validator (integration-test.sh).
# Run from Git Bash on Windows: Go runs on Windows, the validator in WSL.
# Requires `make anchor-build` first.
#
# Sets ROOT, WSL_ROOT, RPC_URL, PROGRAM_ID and VALIDATOR_LOG, and provides:
#   start_validator   start the validator and wait until it is healthy
#   stop_validator    stop it (also safe to call from an EXIT trap)

for tool in cygpath wsl go; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "'$tool' not found: run this from Git Bash on Windows (not from WSL, whose 'bash' may be first on PATH)." >&2
		echo "From PowerShell: & 'C:\\Program Files\\Git\\bin\\bash.exe' $0" >&2
		exit 1
	}
done

export MSYS_NO_PATHCONV=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WSL_ROOT="$(wsl -e wslpath -a "$(cygpath -w "$ROOT")" | tr -d '\r')"
RPC_URL="http://127.0.0.1:8899"
VALIDATOR_LOG="$ROOT/.local/validator.log"
mkdir -p "$ROOT/.local"

PROGRAM_ID="$(wsl -e bash "$WSL_ROOT/scripts/localnet.sh" program-id | tr -d '\r')"

start_validator() {
	# Generates the test keypair on first run, then holds the validator in the
	# foreground of this background job.
	wsl -e bash "$WSL_ROOT/scripts/localnet.sh" run >"$VALIDATOR_LOG" 2>&1 &
	VALIDATOR=$!

	echo "waiting for validator..."
	for _ in $(seq 1 90); do
		if curl -s -X POST -H 'Content-Type: application/json' \
			-d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' "$RPC_URL" | grep -q '"ok"'; then
			return 0
		fi
		if ! kill -0 "$VALIDATOR" 2>/dev/null; then
			echo "validator exited; log:" >&2
			cat "$VALIDATOR_LOG" >&2
			return 1
		fi
		sleep 1
	done
	echo "validator did not become healthy; log:" >&2
	cat "$VALIDATOR_LOG" >&2
	return 1
}

stop_validator() {
	kill "${VALIDATOR:-}" 2>/dev/null || true
	wsl -e pkill -f solana-test-validator 2>/dev/null || true
}
