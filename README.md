# Tokenized Identity KYC

A privacy-preserving, reusable KYC credential system: a trusted issuer signs a
credential, the user holds it, and applications verify it — checking issuer
trust and credential status against a Solana registry — without ever seeing the
user's identity documents.

Full design: [`docs/td_init_project.md`](docs/td_init_project.md).

**Current status: Phase 0** — Go service skeleton (config, structured logging,
HTTP server with health/readiness endpoints). No credential logic or on-chain
program yet.

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

## HTTP endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/healthz` | Liveness: the process is up. Never checks dependencies. |
| `GET` | `/readyz` | Readiness: runs registered dependency checks (none yet; PostgreSQL and Solana RPC will be added). Returns `503` with per-check `ok`/`fail` if any fails; error details are logged, not returned. |

## Project layout

```text
cmd/api/              Entry point: load config, build logger, run app, handle signals
internal/app/         Wires dependencies; owns server lifecycle and graceful shutdown
internal/config/      Environment-variable configuration with validation
internal/httpapi/     Router, middleware (request logging, panic recovery), handlers
internal/logging/     slog logger construction
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
