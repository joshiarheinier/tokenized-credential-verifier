# Credential Types

The system carries any credential whose claims are described by a schema. KYC status is the first type; a ticket or a membership would be others. Nothing in the credential, verification, registry or Solana code is specific to a type.

Where this file and `td_init_project.md` disagree, this file reflects the current code (the TD was written when the project was KYC-only).

## What is generic and what is per type

| Piece | Generic? |
|---|---|
| Signing, signature and expiry checks (`internal/credential`) | Yes |
| On-chain issuer trust and revocation (`pkg/connector/blockchain`, the Anchor program) | Yes. The program never sees a credential type or claims. |
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
	Require:  []verification.Requirement{{Claim: "tier", Equals: "gold"}},
	Disclose: []string{"tier"},
}
```

- `Require`: claims that must have these exact values. A missing claim never satisfies a requirement.
- `Disclose`: the claims returned to the application on success. Leave it nil to return all of them; set it to return only what the application needs.
- A credential whose type has no policy is rejected as `unsupported`: an application accepts only the types it has said it understands.

## Adding a credential type

1. Define its `Schema` (the KYC one is in `internal/credential/kyc`).
2. In `internal/app/app.go`, `credentialTypes()`: add the schema to `credential.NewSchemas(...)` and add a `Policy` for it.
3. Issuance: whatever approves an issuance (an identity check, a purchase) produces a `credential.Approval{Subject, CredentialType, Claims}`. In development the `/v1/approvals/simulate` endpoint creates one for any registered type.

No change is needed to verification, the registry or the Solana program.

## Limitation: issuers are not scoped to types

The registry records that an issuer is trusted, not which credential types it may issue. Today the verifier trusts only this process's own issuer key, so there is no exposure. Once several issuers share a registry, a trusted ticketing issuer could sign a `KYCStatus` credential and a verifier with a KYC policy would accept it. Two ways to close that, to be decided before multi-issuer support:

- relying applications name the issuers they accept per type (a field on `Policy`), or
- the program records which types each issuer may issue and verification checks it on chain.
