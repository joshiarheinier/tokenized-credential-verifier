# Trying the end-to-end flow by hand

Every component runs on its own, in its own terminal, and talks to the others
over the network. Nothing here depends on a particular shell, except that the
Solana validator runs in WSL (see the README for why).

```text
demo-wallet ──presents──▶ demo-dapp ──verify──▶ backend (cmd/api) ──reads/writes──▶ Solana validator
     └──────────requests a credential──────────────▲                                       ▲
                                         curl ──▶ onchaininspect ──────reads─────────────┘
```

| Component | Where it runs | Default address |
|---|---|---|
| Solana validator + registry program | WSL | `http://127.0.0.1:8899` |
| Backend (`cmd/api`) | Windows | `http://127.0.0.1:8080` |
| On-chain inspector (`cmd/onchaininspect`) | Windows | `http://127.0.0.1:9100` |
| Demo dApp (`demo-dapp/`) | Windows | `http://127.0.0.1:9090` |
| Demo wallet (`demo-wallet/`) | Windows | interactive prompt |

Prerequisite: the program is built (`make anchor-build`, see the README). All
commands run from the repository root unless noted.

## 1. Start the chain (two WSL terminals)

```bash
bash scripts/localnet.sh run     # leave running; every run starts from an empty chain
bash scripts/localnet.sh fund    # once the validator is up: creates the issuer's key, airdrops SOL
```

## 2. Configure and start the backend

Generate an issuer signing seed with `go run ./cmd/issuerkeygen`, and save this
as `.local/demo.env` (git-ignored), pasting your seed:

```text
APP_ENV=development
HTTP_ADDR=127.0.0.1:8080
ISSUER_ID=did:example:demo-issuer
ISSUER_SIGNING_KEY_SEED=<the seed>
SOLANA_RPC_URL=http://127.0.0.1:8899
SOLANA_PROGRAM_ID=6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy
SOLANA_REGISTRY_AUTHORITY_KEYPAIR=.local/test-authority-keypair.json
SOLANA_ISSUER_AUTHORITY_KEYPAIR=.local/demo-issuer-authority-keypair.json
SOLANA_BOOTSTRAP=true
APPROVAL_SIMULATION_ENABLED=true
```

(`bash scripts/localnet.sh program-id` prints the program id if yours differs.)

```bash
go run ./cmd/api -env-file .local/demo.env
```

On start, `SOLANA_BOOTSTRAP` creates the registry and registers this issuer. It
is a development convenience and is refused in production. Real environment
variables override the file.

## 3. Start the on-chain inspector, the dApp and the wallet

```bash
go run ./cmd/onchaininspect -program 6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy
cd demo-dapp && go run .          # prompt: status, log, help, quit
cd demo-wallet && go run .        # prompt: request, list, present, help, exit
```

## 4. Use it

In the wallet prompt:

| Command | What it does |
|---|---|
| `request` | Gets a KYC credential from the issuer (the backend signs it and registers it on chain) and stores it |
| `request -kyc-verified=false` | Same, for a person who failed KYC |
| `request -country SG -over-18=false` | Other claim values |
| `list` | Shows stored credentials |
| `present` | Presents the newest credential to the dApp (`present -id <id>` for another) |

`present` prints `granted` with the claims the app learned, or `denied` with a
coarse reason. The dApp prompt shows each decision as it happens (`log` lists
them; `status` checks that the verifier is reachable). The dApp's own
`verify <credential>` does the same as a wallet's `present`, for a token you
paste in (the `credential` field of a file in the wallet's `.wallet` folder).

Expected: a normal `request` then `present` is **granted**; after
`request -kyc-verified=false`, `present` is **denied** (`policy_not_satisfied`).

## 5. Look at the on-chain data

```bash
curl http://127.0.0.1:9100/registry       # authority, paused, version
curl http://127.0.0.1:9100/issuers        # issuer id, signing key, authority, active
curl http://127.0.0.1:9100/credentials    # credential ref, issuer id, state, expiry
```

(In Windows PowerShell 5.1 write `curl.exe`; plain `curl` is a different command there.)

Only hashes and status are on chain. Each credential's `ref` and each issuer's
`issuer_id` are SHA-256-derived ids, and the claims never leave the credential.
Run `request` and watch `/credentials` gain an entry. `account` is the address
you can also look up with `solana account <address> --url http://127.0.0.1:8899`
in WSL.

## Starting over

Restarting the validator (`localnet.sh run`) wipes the chain. After that,
restart the backend (it re-registers the issuer) and clear the wallet's
credentials: they were registered on the old chain, so the verifier would
reject them as not registered. The wallet stores them in `./.wallet` of the
directory you started it from (override with `-dir` or `WALLET_DIR`).

## 6. Try the rejections

Each case below ends with a different reason from the dApp. The wallet commands
are typed at the wallet prompt; the `curl` lines are plain HTTP calls to the
backend (use `curl.exe` in Windows PowerShell 5.1).

**Revoked.** `request`, `present` (granted), then `revoke`, then `present`
again: **denied (`revoked`)**. `curl http://127.0.0.1:9100/credentials` shows the
same record with `"state": "revoked"`. Revocation is a transaction on Solana, it
cannot be undone, and doing it twice is harmless. The token is unchanged and
still validly signed: the chain is what says otherwise. (`revoke` in the wallet
is a demo shortcut; in real life the issuer revokes.) The same call without the
wallet: `curl -X POST http://127.0.0.1:8080/v1/credentials/revoke -d '{"credential":"<token>"}'`.

**Untrusted issuer.** With a credential in the wallet that is granted:

```bash
curl -X POST http://127.0.0.1:8080/v1/issuer/suspend
```

`present` is now **denied (`untrusted_issuer`)**, and `/issuers` shows
`"active": false`. A new `request` also fails (the program refuses to register
credentials for a suspended issuer; the wallet shows an HTTP 500 for it).
`curl -X POST http://127.0.0.1:8080/v1/issuer/reactivate` makes the same
credential verify again. These two endpoints act on this backend's own issuer
and exist only because the demo's backend holds the registry authority key.

**Expired.** Add `CREDENTIAL_TTL=30s` to `.local/demo.env` and restart the
backend. `request`, wait 30 seconds, `present`: **denied (`expired`)**.

**Chain outage.** With a credential in the wallet, stop the validator and
`present`: **denied (`verification_unavailable`)**, with HTTP 503. When the
trust state cannot be read the credential is never accepted. Start the
validator again to recover (remember that it wipes the chain, see below).

The revoke and suspend endpoints are development conveniences like the
simulated approvals and issuance: they are only registered when
`APPROVAL_SIMULATION_ENABLED` is on, they answer 501 if no registry is
configured, and they have no authentication yet.

## 7. The browser wallet, with Phantom

A web wallet that keeps credentials in your browser and uses your Phantom account
as the holder key. Phantom only signs a short text; it holds none of the
credentials, sends no transaction and needs no funds or network setup. The demo
application is a members-only page that asks the wallet to prove one claim, being
over 18, and learns nothing else.

**Setup.** Install the Phantom browser extension and create or pick any test
account. Add the wallet's origin to the backend's `.local/demo.env` and restart the
backend (use `localhost`, not `127.0.0.1`, in the browser):

```text
CORS_ALLOWED_ORIGINS=http://localhost:9091
```

Then start the wallet and the application, each in its own terminal:

```bash
cd demo-wallet && go run . serve      # http://localhost:9091
cd demo-dapp && go run .              # http://localhost:9090
```

The wallet talks to `http://127.0.0.1:8080` by default (`-verifier` and
`-issuer` change that, as do `VERIFIER_URL` and `ISSUER_URL`).

**1. Get a credential.** Open <http://localhost:9091>, press *Connect Phantom*
(approve in the extension), then *Get credential*. It appears in the list as
*bound to this account*: its subject is your Phantom address. You can open its
claims and delete it.

**2. Verify on the application's page.** Open <http://localhost:9090> and press
*Verify with wallet*. The application poses a challenge for `over_18` and sends
you to your wallet. The wallet shows who is asking (`http://localhost:9090`),
which claim, and what your credential would share (`over_18 = true`). Press
*Approve and sign with Phantom*: Phantom shows the exact text being signed, which
is also your consent record. The wallet says *Verified* and you follow its link
back to the application, which opens the members area. It lists what it
learned, only `over_18`: not your country, not the KYC flag. Press *Sign out*
to close the area again.

The dApp prompt in its terminal shows each step as it happens (`asked a wallet
to prove over_18`, `wallet answered: over_18 = true`).

**Playing the application yourself, with curl.** The same flow without the page.
In Git Bash:

```bash
curl -X POST http://127.0.0.1:8080/v1/challenges -H "Content-Type: application/json" \
  -d '{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"]}'
```

(In Windows PowerShell: `Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/challenges -ContentType application/json -Body '{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"]}'`.)
Keep the `challenge_id` and `result_secret` from the reply.

Open `http://localhost:9091/present?challenge=<challenge_id>` and answer it in the
wallet as above. Then read the verdict, as the application:

```bash
curl http://127.0.0.1:8080/v1/challenges/<challenge_id>/result -H "Authorization: Bearer <result_secret>"
```

It holds only `over_18`, not your country or the KYC flag.

**Things to try.** On the application's page, press *Verify with wallet* and
*Decline* in the wallet: the application says it is still waiting and lets
nobody in. Request a credential with *Over 18* unticked and verify with it: the
application learns `over_18 = false` and refuses entry. Stop the backend and press
*Verify with wallet*: *cannot verify right now*, and nobody is let in. Reload the
consent page after answering: *already answered* (a challenge works once). Switch to another Phantom account and open a fresh
challenge: the credential is listed as *not usable* because it was issued to a
different account. Decline in Phantom: nothing is sent. Press *Revoke (demo)*
on a credential: the issuer revokes it on chain (`/credentials` on the inspector
shows `revoked`), and a challenge answered with it is then refused by the
verifier. *Remove from wallet* is different: it only deletes this wallet's copy
and does not revoke anything, so the credential stays valid on chain. Revoking
needs the credential, so revoke before you remove it.

**If something does not work.** On the application's page, *This page only works
in the browser that started the verification*: open the application as
`http://localhost:9090` (it redirects `127.0.0.1` there) and start again from its
home page. *Could not reach http://127.0.0.1:8080 … CORS*:
the backend does not list the wallet's origin in `CORS_ALLOWED_ORIGINS`.
*Phantom was not found*: reload after installing, and open the wallet as
`http://localhost:9091`. The wallet serves a strict Content-Security-Policy; if
Phantom is installed but never detected, that is the first thing to suspect.

**Testing the wallet's code.** Its protocol logic is plain JavaScript with Node
tests in `demo-wallet/webtest`, including a check that a signature made in
JavaScript is accepted by the Go verifier. Node is not on the Windows path here
but is in WSL: `cd demo-wallet && node --test`.
