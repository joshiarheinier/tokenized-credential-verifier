# Tokenized Identity KYC

A privacy-preserving, reusable KYC credential system: a trusted issuer signs a
credential, the user holds it, and applications verify it — checking issuer
trust and credential status against a Solana registry — without ever seeing the
user's identity documents.

Full design: [`docs/td_init_project.md`](docs/td_init_project.md).

**Current status: Phase 1** — off-chain credential MVP: simulated KYC, signed
Ed25519 credentials, and a verification endpoint. Nothing depends on a
blockchain yet; the Solana registry arrives in Phases 2-3.

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
git clone <repo-url> tokenized-identity-kyc
cd tokenized-identity-kyc

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
| `KYC_SIMULATION_ENABLED` | `true` (`false` in production) | Enables the simulate/issue endpoints. The process refuses to start with this on in production. |

Generate an issuer signing seed with `go run ./cmd/issuerkeygen` (the seed is
printed to stdout, the public key and key id to stderr).

## HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness: the process is up. Never checks dependencies. |
| `GET` | `/readyz` | Readiness: runs registered dependency checks (none yet; PostgreSQL and Solana RPC will be added). Returns `503` with per-check `ok`/`fail` if any fails; error details are logged, not returned. |

### Credential endpoints (Phase 1)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/kyc/simulate` | **Dev only.** Records a simulated KYC decision. Body: `{"subject","outcome":"approved"\|"rejected","over_18","country"}` (country = ISO alpha-2, required when approved). Returns `201 {"kyc_result_id"}`. |
| `POST` | `/v1/credentials` | **Dev only.** Body: `{"kyc_result_id"}`. Issues a credential for an approved result, **once** (`404` unknown, `422` rejected, `409` already used). Returns `201 {"credential","expires_at"}`. |
| `POST` | `/v1/credentials/verify` | Body: `{"credential"}`. Always `200` for a well-formed request: `{"valid":true,"issuer","credential_type","expires_at","claims"}` or `{"valid":false,"reason"}`. |

Verification `reason` codes: `malformed`, `unsupported`, `untrusted_issuer`,
`invalid_signature`, `expired`, `not_yet_valid`, `policy_not_satisfied`. The
subject and credential id are not returned to the verifying application.

Try it:

```sh
ID=$(curl -s localhost:8080/v1/kyc/simulate -d '{"subject":"user-1","outcome":"approved","over_18":true,"country":"ID"}' | sed 's/.*"kyc_result_id":"\([^"]*\)".*/\1/')
CRED=$(curl -s localhost:8080/v1/credentials -d "{\"kyc_result_id\":\"$ID\"}" | sed 's/.*"credential":"\([^"]*\)".*/\1/')
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
credentials whose `iss` does not match the key's issuer. Claims are coarse
(`kyc_verified`, `over_18`, `country`); no names, birthdates or documents.

Phase 1 limitations: the simulated KYC store is in memory (lost on restart),
and the verifier trusts only this process's own issuer key. Issuer trust moves
to the Solana registry in later phases.

## Project layout

```text
cmd/api/              Entry point: load config, build logger, run app, handle signals
internal/app/         Wires dependencies; owns server lifecycle and graceful shutdown
internal/config/      Environment-variable configuration with validation
internal/httpapi/     Router, middleware (request logging, panic recovery), handlers
internal/logging/     slog logger construction
internal/credential/  Credential model, Ed25519 signer, verifier, issuing service (no chain dependency)
internal/issuer/      Issuer identity and signing-key loading
internal/identity/    Simulated KYC decisions (dev only, in memory)
internal/verification/ Acceptance policy and coarse rejection reasons
cmd/issuerkeygen/     Generates an issuer signing seed
docs/                 Technical design
```

Packages from the target layout in the design doc (`credential`, `issuer`,
`verification`, `blockchain`, `repository`, `contracts/`, `migrations/`,
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
Rust/Solana/Anchor versions in `contracts/kyc-registry` (`rust-toolchain.toml`,
`Anchor.toml`) and record them in the requirements table above.
