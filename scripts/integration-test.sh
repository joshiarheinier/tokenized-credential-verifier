#!/usr/bin/env bash
# Runs the Go integration tests against a local validator started in WSL.
# Run from Git Bash on Windows (Go runs on Windows, the validator in WSL).
# Requires `make anchor-build` first.
set -euo pipefail

# shellcheck source=lib/validator.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/validator.sh"

trap stop_validator EXIT
start_validator

cd "$ROOT"
# Default to every package; -p 1 runs packages one at a time since they share
# one validator.
if [ "$#" -eq 0 ]; then set -- ./internal/... ./cmd/...; fi
CREDENTIAL_TEST_RPC_URL="$RPC_URL" \
CREDENTIAL_TEST_PROGRAM_ID="$PROGRAM_ID" \
CREDENTIAL_TEST_AUTHORITY_KEYPAIR="$(cygpath -m "$ROOT/.local/test-authority-keypair.json")" \
	go test -tags integration -count=1 -p 1 "$@"
