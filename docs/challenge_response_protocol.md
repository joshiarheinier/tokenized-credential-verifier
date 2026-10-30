# Challenge-response protocol (v1)

How a holder proves a credential to a relying application, bound to that
application and to one session. A relying application poses a *challenge*; the
holder's wallet answers it with a *response*: the credential plus a signature,
made with the holder's key, over the challenge. (In the wider credential
ecosystem, W3C Verifiable Credentials and OpenID4VP, this response is called a
*presentation*; this project says "response" because that is what it is.)

This is the specification that the backend (`cmd/api`), the wallet
(`demo-wallet`) and the demo application (`demo-dapp`) are built against. The
plan is `phase5_devplan.md`; the scope source of truth is `td_init_project.md`,
which uses the word "presentation" for what this document calls a response.

Decisions behind it: the holder key is the user's Phantom (Ed25519) account; the
credential's subject is `solana:<address>`; selective disclosure is verifier-side
for now (section 10).

## 1. Roles

| Role | Is | Does |
|---|---|---|
| **Relying application** | `demo-dapp`, or any app | Wants to know a claim about a user. Creates a challenge, sends the user's browser to the wallet, then reads the verdict from the verifier. |
| **Verifier** | the backend (`cmd/api`) | Holds the challenge, checks the response, remembers the verdict. |
| **Holder** | the user, through the wallet app and Phantom | Reviews the request, consents by signing, and submits the credential. |

The relying application never receives the credential or the holder's
signature. It receives only the verdict and the claims it asked for, and only
from the verifier, never through the browser.

## 2. Identifiers

- **Holder id** (a credential's `sub`): `solana:` followed by the base58 form of
  the holder's 32-byte Ed25519 public key, for example
  `solana:Dd1WCC8TmCwdKLgHxQ9jNEEXgzqHCBCWLsyr1GtSdVSh`. This is exactly the
  address Phantom shows. A credential whose `sub` is not in this form cannot be
  used to answer a challenge (`holder_binding_failed`).
- **Challenge id**: 128 random bits, base64url without padding. It is public: it
  travels through the browser and is also the nonce in the signed message.
- **Result secret**: 256 random bits, base64url without padding. Returned only to
  the party that created the challenge. It never goes through the browser.
- **Audience**: the origin of the relying application, `scheme://host[:port]`,
  with no path. It must be `https`, or `http` for `localhost` and `127.0.0.1`
  (development). ASCII only.

## 3. Challenge lifecycle

```text
                 response (any outcome)
  pending ───────────────────────────────▶ completed (verified | rejected | unavailable)
     │
     └── time passes ──▶ expired
```

- A challenge is valid for `CHALLENGE_TTL` (default 5 minutes) from creation.
- It is **consumed atomically by the first response attempt**, whatever the
  outcome. A second attempt, concurrent or later, gets 409. If verification
  could not be completed (chain unreachable) the challenge is still consumed and
  the application starts a new one.
- The verdict stays readable by the creator until 5 minutes after the challenge
  expires, then the record is deleted.
- The store is in memory in this version: restarting the backend forgets
  challenges, and it must not be run as more than one instance (section 10).

## 4. Endpoints

All bodies are JSON. The usual limits apply (16 KiB request body, unknown fields
rejected). Errors are `{"error": "<message>"}`.

### 4.1 `POST /v1/challenges` (relying application → verifier)

```json
{
  "audience": "http://localhost:9090",
  "credential_type": "KYCStatus",
  "claims": ["over_18"],
  "callback_url": "http://localhost:9090/callback"
}
```

- `claims`: the claims the application wants, 1 to 16 distinct names matching
  `^[a-z][a-z0-9_]{0,63}$`. Only these are returned in the verdict.
- `callback_url`: optional. If present it must have the same origin as
  `audience`. The wallet sends the user back there when done.

`201 Created`:

```json
{
  "challenge_id": "q3f...",
  "result_secret": "n8k...",
  "audience": "http://localhost:9090",
  "credential_type": "KYCStatus",
  "claims": ["over_18"],
  "callback_url": "http://localhost:9090/callback",
  "expires_at": "2026-11-03T10:15:00Z"
}
```

`400` for an invalid audience, claim list or callback.

### 4.2 `GET /v1/challenges/{id}` (wallet → verifier)

What the wallet needs for its consent screen. No secret in it.

```json
{
  "challenge_id": "q3f...",
  "status": "pending",
  "audience": "http://localhost:9090",
  "credential_type": "KYCStatus",
  "claims": ["over_18"],
  "callback_url": "http://localhost:9090/callback",
  "expires_at": "2026-11-03T10:15:00Z"
}
```

`status` is `pending` or `completed`. `404` if unknown, `410` if expired.

### 4.3 `POST /v1/challenges/{id}/response` (wallet → verifier)

```json
{
  "credential": "<compact credential token>",
  "holder_signature": "<standard base64 of the 64-byte Ed25519 signature>"
}
```

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"status":"verified"}` | Accepted. The verdict is stored for the application. |
| `200` | `{"status":"rejected","reason":"<code>"}` | Refused; see the reasons in section 7. |
| `503` | `{"status":"unavailable","reason":"verification_unavailable"}` | Trust state could not be established. Nothing is accepted. |
| `400` | `{"error":...}` | Malformed request or signature encoding. The challenge is **not** consumed. |
| `404` / `410` / `409` | `{"error":...}` | Challenge unknown / expired / already used. |

The answer to the wallet never includes claims. Only the creator of the challenge can read
them.

### 4.4 `GET /v1/challenges/{id}/result` (relying application → verifier)

Authenticated by the result secret in `Authorization: Bearer <result_secret>`.
An unknown id and a wrong secret both give `404`, so ids cannot be probed; a
missing bearer token gives `401`.

```json
{ "status": "pending" }
{ "status": "verified", "issuer": "did:example:issuer-dev", "credential_type": "KYCStatus",
  "claims": { "over_18": true }, "credential_expires_at": "2026-12-03T10:10:00Z" }
{ "status": "rejected", "reason": "revoked" }
{ "status": "unavailable", "reason": "verification_unavailable" }
{ "status": "expired" }
```

`claims` holds exactly the claims requested at creation. Reading is repeatable.

## 5. The signed message

The holder signs the **UTF-8 bytes** of this text, with `\n` line breaks and no
trailing newline. Phantom shows it to the user, so it is also the consent
record. The wallet builds it from the challenge and its credential; the verifier
rebuilds it from the stored challenge and the credential in the response and checks
the signature over its own copy, so there is nothing for the two to disagree
about except the bytes below.

```text
tcv-challenge-response/v1
audience: <audience>
challenge: <challenge id>
type: <credential type>
claims: <requested claims, sorted ascending, joined with ",">
credential: sha256:<lowercase hex of SHA-256 of the credential token's bytes>
expires: <challenge expiry, UTC, as 2006-01-02T15:04:05Z>
```

Example:

```text
tcv-challenge-response/v1
audience: http://localhost:9090
challenge: AAAAAAAAAAAAAAAAAAAAAA
type: KYCStatus
claims: over_18
credential: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
expires: 2026-11-03T10:15:00Z
```

(This exact example is pinned by a test in `internal/domain/challenge`, so the
wallet's JavaScript can be checked against it.)

Each line is there for a reason: the first line separates this protocol from any
other use of the same key; `audience` and `challenge` bind the signature to one
application and one session; `type` and `claims` show what is being disclosed;
`credential` binds it to one credential; `expires` shows the user the window.

## 6. What the verifier checks, in order

On `POST /v1/challenges/{id}/response`:

1. The request is well formed and the signature is 64 bytes of base64
   (otherwise `400`, challenge untouched).
2. The challenge exists and has not expired (`404`/`410`).
3. **Consume the challenge atomically** (`409` if it was already consumed).
4. The credential verifies exactly as for any credential: issuer signature, the
   issuer's key and active status from the on-chain registry, credential
   registered, not revoked, not expired, policy satisfied. Any failure is
   `rejected` with that reason; an unreadable chain is `unavailable`.
5. Its credential type equals the challenge's (`wrong_credential_type`).
6. **Holder binding:** `sub` is a holder id, and the signature verifies, under
   the key in `sub`, over the message of section 5 (`holder_binding_failed`).
7. Every requested claim is present and disclosable under the verifier's
   policy for that type (`claim_unavailable`).
8. Store the verdict with only the requested claims.

## 7. Reasons

From credential verification (unchanged): `malformed`, `unsupported`,
`untrusted_issuer`, `invalid_signature`, `expired`, `not_yet_valid`,
`policy_not_satisfied`, `not_registered`, `revoked`, `verification_unavailable`.

Added by this protocol: `wrong_credential_type`, `holder_binding_failed`,
`claim_unavailable`.

Reasons are deliberately coarse. `holder_binding_failed` covers both a `sub`
that is not a holder id and a signature that does not verify.

## 8. The browser flow

```text
1. App server  → Verifier : POST /v1/challenges            (keeps result_secret)
2. App page    → Wallet   : open  <wallet>/present?challenge=<id>[&verifier=<verifier base URL>]
3. Wallet      → Verifier : GET /v1/challenges/<id>        (consent screen)
4. Wallet      → Phantom  : signMessage(message)           (user approves)
5. Wallet      → Verifier : POST /v1/challenges/<id>/response
6. Wallet      → App page : redirect to callback_url?challenge=<id>
7. App server  → Verifier : GET /v1/challenges/<id>/result  (Bearer result_secret)
```

**The wallet sends a credential only to the verifier it is configured with.** The
`verifier` parameter in the link is optional; if it is present and differs from
the wallet's configured verifier, the wallet refuses the request. Otherwise any
application could point the wallet at its own server and collect credentials.

The wallet redirects only to the `callback_url` the verifier returned for that
challenge, which has the audience's origin, so it cannot be used as an open
redirect. The page that lands on the callback learns nothing from the URL except
the challenge id; it asks its own server, which asks the verifier.

Because the wallet runs in a browser on another origin than the verifier, the
verifier answers CORS preflights for the origins in `CORS_ALLOWED_ORIGINS`, for
the `Content-Type` header only. `Authorization` is deliberately not allowed
cross-origin: the result endpoint is for servers.

## 9. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CHALLENGE_TTL` | `5m` | How long a challenge can be answered. |
| `CORS_ALLOWED_ORIGINS` | empty | Comma-separated origins allowed to call the API from a browser, e.g. the wallet's. Empty allows none. |

## 10. Threats and limitations

| Threat | Defence | Proven by |
|---|---|---|
| Replaying a response | Challenge consumed on first attempt; expiry | Step 5 tests |
| Using a response at another application | Audience and challenge inside the signed text | Step 5 tests |
| A stolen credential presented by someone else | Signature must come from the key in `sub` | Step 5 tests |
| Moving a signature to a different credential | Credential hash inside the signed text | Step 5 tests |
| A rogue app reading a verdict it did not request | Result needs the secret, which never leaves the creating server | Step 5 tests |
| Probing challenge ids | Unknown id and wrong secret are indistinguishable | Step 5 tests |
| Treating an outage as success | `unavailable`, never `verified` | Existing scenario tests |
| Open redirect through the wallet | Redirect only to the challenge's own callback, same origin as audience | Step 5 tests |

Accepted limitations, to be stated in the integration guide:

- **Verifier-side selective disclosure.** The wallet sends the whole credential;
  the verifier returns only the requested claims to the application. The
  verifier operator sees all claims. Hiding claims from the verifier is Phase 6.
- **The Phantom address is the holder id**, so verifiers that see credentials
  can link the same user by address. Pairwise ids are Phase 6.
- **Anyone can create a challenge for any audience** until relying-party API
  keys are added (step 5). The wallet shows the audience to the user, and the
  result secret keeps the verdict private, but a malicious application can name
  another application's origin.
- **In-memory store**, single instance, with a cap on open challenges.
- **Credentials are bound only if issued with a holder id as `sub`.** Issuing
  does not check that the requester controls that key; a credential bound to
  someone else's key is simply useless to the person who obtained it.
