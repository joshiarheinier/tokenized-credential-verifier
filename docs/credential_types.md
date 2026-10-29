# Credential Types

The system carries any credential whose claims are described by a schema. KYC status is the first type; a ticket or a membership would be others. Nothing in the credential, verification, registry or Solana code is specific to a type.

Where this file and `td_init_project.md` disagree, this file reflects the current code (the TD was written when the project was KYC-only).

## What is generic and what is per type

| Piece | Generic? |
|---|---|
| Signing, signature and expiry checks (`internal/credential`) | Yes |
| On-chain issuer trust and revocation (`internal/infrastructure/client/blockchain`, the Anchor program) | Yes. The program never sees a credential type or claims. |
| Which claims a type has, and their kinds | Per type: a `credential.Schema` |
| What a relying application demands of a type | Per application: a `verification.Policy` |

## Schema

A `credential.Schema` names the type and lists its claims:

```go
credential.Schema{
	Type: "Membership",
	Fields: []credential.Field{
		{Name: "tier", Kind: credential.String, Required: true},
		{Name: "member_since", Kind: credential.Number},
	},
}
```

Kinds are `Bool`, `String` and `Number`. A field can carry a `Check` function for extra rules (the KYC `country` claim must be two uppercase letters).

Validation is strict by design: a claim not listed in the schema is rejected, both when issuing and when verifying. This is how the system keeps credentials to the minimum facts a type needs, and stops an issuer attaching personal data the schema never approved.

## Policy

A `verification.Policy` says what one relying application requires of one type:

```go
verification.Policy{
	CredentialType: "Membership",
	Require:         []verification.Requirement{{Claim: "tier", Equals: "gold"}},
	Disclose:        []string{"tier"},
	AcceptedIssuers: []string{"did:web:club.example"},
}
```

- `Require`: claims that must have these exact values. A missing claim never satisfies a requirement.
- `Disclose`: the claims returned to the application on success. Leave it nil to return all of them; set it to return only what the application needs.
- `AcceptedIssuers`: the issuers (`iss` values) whose credentials of this type are accepted. Empty accepts any issuer the registry trusts, so set it whenever more than one issuer is trusted. A credential from an unlisted issuer is rejected as `untrusted_issuer` before the chain is consulted.
- A credential whose type has no policy is rejected as `unsupported`: an application accepts only the types it has said it understands.

## Adding a credential type

1. Define its `Schema` (the KYC one is in `internal/credential/kyc`).
2. In `internal/app/app.go`, `credentialTypes()`: add the schema to `credential.NewSchemas(...)` and add a `Policy` for it, naming the issuers you accept for it.
3. Issuance: whatever approves an issuance (an identity check, a purchase) produces a `credential.Approval{Subject, CredentialType, Claims}`. In development the `/v1/approvals/simulate` endpoint creates one for any registered type.

No change is needed to verification, the registry or the Solana program.

## Issuers and credential types

The registry records that an issuer is trusted, not which credential types it may issue. Without more, once several issuers share a registry a trusted ticketing issuer could sign a `KYCStatus` credential and a verifier would accept it.

Each application closes that for itself with `AcceptedIssuers`: for every type it accepts, it names the issuers it expects. A ticketing issuer that is not on the KYC policy's list cannot mint a KYC credential that application accepts. The default deployment lists only its own issuer.

What this does not do is have the registry itself say which types an issuer is authorised for. If the registry authority should enforce that centrally, the Anchor program would record allowed types on each issuer and verification would check them on chain. That is a program change and is not implemented.
