# Tokenized Credential Verifier

A privacy-preserving, reusable credential verification system: a trusted issuer
signs a credential, the holder keeps it, and applications verify it — checking
issuer trust and credential status against a Solana registry — without the
issuer's underlying records ever being shared. It is meant to serve as shared
infrastructure for different credential products. The first credential type is
KYC status (simulated); other uses such as ticketing or memberships are future
work.

Full design: [`docs/td_init_project.md`](docs/td_init_project.md) (written when
this was a KYC-only project; its KYC framing predates the rename).

**Current status: Phase 3** — signed Ed25519 credentials, the Solana registry
program, and the Go backend verifying against it. Issuance uses simulated approvals.

## Requirements

| Tool | Version | Needed for |
|---|---|---|
| Go | **1.26+** (see `go.mod`) | Backend (all phases) |
| Git | any recent | Source control |
| GNU Make | optional | Shortcuts below; every target is a plain `go` command |
| Rust, Solana CLI, Anchor | see [Solana toolchain](#solana-toolchain-phase-2) | On-chain program (Phase 2+) only |

The Go backend has no dependency on the Solana toolchain; you can build and
test it without installing Rust, Solana or Anchor.

## Quick start

```sh
git clone <repo-url> tokenized-credential-verifier
cd tokenized-credential-verifier

cp .env.example .env    # optional; every variable has a default
go test ./...
go run ./cmd/api
```

In another terminal:

```sh
curl -i http://localhost:8080/healthz   # 200 {"status":"ok"}
curl -i http://localhost:8080/readyz    # 200 {"status":"ready"}
```

Stop the server with `Ctrl+C`; it shuts down gracefully.

### Loading `.env`

The process reads **environment variables only**; it does not parse `.env`
itself. `make run` loads `.env` automatically. Without Make:

```sh
# bash / Git Bash / WSL
set -a; . ./.env; set +a; go run ./cmd/api
```

```powershell
# PowerShell
Get-Content .env | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
  $k, $v = $_ -split '=', 2; Set-Item "env:$($k.Trim())" $v.Trim() }
go run ./cmd/api
```

## Make targets

| Target | Equivalent | Purpose |
|---|---|---|
| `make run` | `go run ./cmd/api` | Run the API (loads `.env`) |
| `make build` | `go build -o bin/ ./cmd/api` | Build the binary |
| `make test` | `go test ./...` | Run all tests |
| `make test-race` | `go test -race ./...` | Tests with race detector (needs cgo/gcc) |
| `make cover` | `go test -coverprofile=...` | Coverage report |
| `make lint` | `gofmt -l .` + `go vet ./...` | Format check and vet |
| `make fmt` | `gofmt -w .` | Format code |
| `make anchor-build` / `anchor-test` | via WSL | Build / test the Anchor program |
| `make integration-test` | `scripts/integration-test.sh` | Go integration tests against a local validator |

On Windows, Make is available via WSL, MSYS2 (`pacman -S make`), or
`winget install GnuWin32.Make`. It is optional.

## Configuration

All configuration comes from environment variables (see `.env.example`).
Invalid values make the process exit at startup with a message naming each bad
variable.

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `development`, `test` or `production` |
| `HTTP_ADDR` | `:8080` | Listen address |
| `HTTP_READ_TIMEOUT` | `10s` | Max time to read a request (incl. headers) |
| `HTTP_WRITE_TIMEOUT` | `15s` | Max time to write a response |
| `HTTP_IDLE_TIMEOUT` | `60s` | Keep-alive idle timeout |
| `HTTP_SHUTDOWN_TIMEOUT` | `15s` | Grace period for in-flight requests on shutdown |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | `json` (machine) or `text` (human) |
| `ISSUER_ID` | `did:example:issuer-dev` | Issuer identifier placed in the `iss` claim |
| `ISSUER_SIGNING_KEY_SEED` | *(empty)* | Base64url 32-byte Ed25519 seed (**secret**). Empty = ephemeral key (non-production only). Required in production. |
| `CREDENTIAL_TTL` | `720h` | Validity period of issued credentials |
| `APPROVAL_SIMULATION_ENABLED` | `true` (`false` in production) | Enables the simulate/issue endpoints. The process refuses to start with this on in production. |
| `SOLANA_RPC_URL` | *(empty)* | RPC endpoint of the registry cluster. Empty = off-chain checks only (non-production). **Required in production.** |
| `SOLANA_PROGRAM_ID` | *(empty)* | Deployed registry program id. Required with `SOLANA_RPC_URL`. |
| `SOLANA_COMMITMENT` | `confirmed` | `confirmed` or `finalized` (used for reads and confirming writes) |
| `SOLANA_REGISTRY_AUTHORITY_KEYPAIR` | *(empty)* | Path to the registry authority keypair (**secret**). Only for administration/bootstrap. |
| `SOLANA_ISSUER_AUTHORITY_KEYPAIR` | *(empty)* | Path to the issuer authority keypair (**secret**). Needed to register issued credentials on chain. |
| `SOLANA_REQUEST_TIMEOUT` | `10s` | Timeout of a single RPC call |
| `SOLANA_TX_TIMEOUT` | `30s` | How long to wait for a submitted transaction to confirm |
| `SOLANA_BOOTSTRAP` | `false` | Dev/test only: create the registry and register this issuer at startup (idempotent). Needs both keypairs and a fixed `ISSUER_SIGNING_KEY_SEED`. Refused in production. |

Generate an issuer signing seed with `go run ./cmd/issuerkeygen` (the seed is
printed to stdout, the public key and key id to stderr).

## HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness: the process is up. Never checks dependencies. |
| `GET` | `/readyz` | Readiness: runs registered dependency checks (none yet; PostgreSQL and Solana RPC will be added). Returns `503` with per-check `ok`/`fail` if any fails; error details are logged, not returned. |

### Credential endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/approvals/simulate` | **Dev only.** Records a simulated issuer approval. Body: `{"subject","credential_type","outcome":"approved"\|"rejected","claims":{...}}`. For an approved outcome the type must be one this deployment supports and `claims` must match its schema (`400` otherwise). Returns `201 {"approval_id","outcome"}`. |
| `POST` | `/v1/credentials` | **Dev only.** Body: `{"approval_id"}`. Issues a credential for an approved result, **once** (`404` unknown, `422` rejected, `409` already used). Returns `201 {"credential","expires_at"}`. |
| `POST` | `/v1/credentials/verify` | Body: `{"credential"}`. `200` for a well-formed request: `{"valid":true,"issuer","credential_type","expires_at","claims"}` or `{"valid":false,"reason"}`. `503` with `{"valid":false,"reason":"verification_unavailable"}` when the on-chain registry could not be read (the credential is not accepted). |

Verification `reason` codes: `malformed`, `unsupported`, `untrusted_issuer`,
`invalid_signature`, `expired`, `not_yet_valid`, `policy_not_satisfied` (`unsupported` also covers a credential type this deployment has no policy for), and with
the registry enabled `not_registered`, `revoked`, `verification_unavailable`. The
subject and credential id are not returned to the verifying application.

Try it:

```sh
ID=$(curl -s localhost:8080/v1/approvals/simulate -d '{"subject":"user-1","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID"}}' | sed 's/.*"approval_id":"\([^"]*\)".*/\1/')
CRED=$(curl -s localhost:8080/v1/credentials -d "{\"approval_id\":\"$ID\"}" | sed 's/.*"credential":"\([^"]*\)".*/\1/')
curl -s localhost:8080/v1/credentials/verify -d "{\"credential\":\"$CRED\"}"
```

### Credential format

A compact JWS (`header.payload.signature`, base64url without padding) signed
with Ed25519 (`alg=EdDSA`), carrying a JWT-style claim set with a `ver`
(format version, currently `1`) claim. It mirrors the shape of a W3C
Verifiable Credential but **does not claim W3C conformance**. The verifier
accepts only `EdDSA`, looks up the key by `kid` among trusted issuer keys,
checks the signature *before* reading claims, rejects unknown fields,
unsupported versions/types, expired or not-yet-valid credentials, and
credentials whose `iss` does not match the key's issuer.

What a credential attests depends on its `credential_type`. Each type has a
schema listing its claims and their kinds, and claims outside the schema are
rejected, so an issuer cannot attach extra (possibly personal) data. KYC status
(`kyc_verified`, `over_18`, `country`) is the first type; others can be added
without touching the credential, verification or registry code. See
[`docs/credential_types.md`](docs/credential_types.md).

Limitations: the simulated approval store is in memory (lost on restart),
and the verifier's local key set is only this process's own issuer key (the
registry is checked on top of it, but does not yet supply other issuers' keys).

## Project layout

```text
cmd/api/              Entry point: load config, build logger, run app, handle signals
internal/app/         Wires dependencies; owns server lifecycle and graceful shutdown
internal/config/      Environment-variable configuration with validation
internal/httpapi/     Router, middleware (request logging, panic recovery), handlers
internal/logging/     slog logger construction
internal/credential/  Credential model, schemas, Ed25519 signer, verifier, issuing service
internal/credential/kyc/ The KYCStatus credential type (first registered type)
internal/issuer/      Issuer identity and signing-key loading
internal/approval/    Issuer approval decisions: recorded once, consumed once at issuance (in memory)
internal/verification/ Acceptance policy, on-chain checks and coarse rejection reasons
pkg/connector/blockchain/ Connector to the Solana registry program (only package importing the SDK; no dependency on internal/)
contracts/credential-registry/ Anchor program (trust registry)
scripts/              Local validator and integration-test runners (WSL)
cmd/issuerkeygen/     Generates an issuer signing seed
docs/                 Technical design
```

Packages from the target layout in the design doc (`repository`, `migrations/`,
`api/openapi.yaml`) are added in the phase that gives them real
responsibilities. `internal/http` from the design is named `internal/httpapi`
so the package doesn't shadow `net/http`.

## Security notes

- Never commit private keys, seed phrases, Solana keypairs, or `.env`. The
  `.gitignore` excludes `.env*` (except `.env.example`), `*.pem`, `*.key`,
  `*-keypair.json`, `id.json`, `keys/` and `secrets/`.
- Request logs record only method, path, status and latency — never headers,
  query strings or bodies, which may carry credentials or personal data.

## Solana toolchain (Phase 2+)

Not needed until Phase 2 (the Anchor registry program). Install it separately
from the Go backend.

**Windows:** Anchor and the Solana CLI are supported on Linux/macOS; on Windows
use **WSL2** (Ubuntu) and run the steps below inside it. The Go backend can stay
on native Windows.

Follow the official guide: <https://solana.com/docs/intro/installation>. It
installs Rust, the Solana CLI, and Anchor (via the Anchor Version Manager,
`avm`). Then verify and configure a local cluster:

```sh
rustc --version
solana --version
anchor --version

solana config set --url localhost
solana-keygen new --outfile ~/.config/solana/id.json   # local dev wallet only
solana-test-validator                                   # local validator
```

Keep keypairs outside the repository. When Phase 2 starts, pin the exact
Rust/Solana/Anchor versions in `contracts/credential-registry` (`rust-toolchain.toml`,
`Anchor.toml`) and record them in the requirements table above.

## Testing against a local validator

`go test ./...` needs no blockchain. The integration tests (build tag
`integration`) run the Go adapter and the application against a real
`solana-test-validator` with the registry program deployed:

```sh
make anchor-build                    # builds the program (WSL)
bash scripts/integration-test.sh     # Git Bash: starts the validator in WSL, runs the tests, stops it
```

Without the environment the script sets up, the integration tests skip. See
`docs/go_solana_integration.md` for how the Go side talks to the program.
