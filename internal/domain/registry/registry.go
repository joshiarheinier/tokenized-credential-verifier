// Package registry is the domain model of the trust registry: which issuers are
// trusted to issue credentials, and what the status of each issued credential
// is. It describes what the registry holds and how credentials and issuers are
// identified in it; where the registry is stored (a Solana program today) is an
// infrastructure concern, implemented in internal/infrastructure/client/
// blockchain.
//
// The registry holds no personal data: issuers are identified by a hash of
// their public identifier, credentials by an opaque reference derived from a
// random credential id.
package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"
)

// Errors reported by registry implementations. Use errors.Is to classify them.
var (
	// ErrNotFound means the record is known to be absent from the registry.
	ErrNotFound = errors.New("registry: record not found")
	// ErrUnavailable means the registry could not be reached or answered
	// unusably. It says nothing about the state of the requested record, so it
	// must never be read as "absent".
	ErrUnavailable = errors.New("registry: unavailable")
	// ErrConflict means a record already exists with different contents than
	// the one requested.
	ErrConflict = errors.New("registry: conflicting record exists")
)

// IssuerRecord is a trusted issuer as the registry records it.
type IssuerRecord struct {
	// IssuerID identifies the issuer; see the IssuerID function.
	IssuerID [32]byte
	// SigningKey is the Ed25519 key the issuer signs credentials with.
	SigningKey ed25519.PublicKey
	// Authority is the public key allowed to register and revoke the issuer's
	// credentials in the registry. It is deliberately separate from SigningKey.
	Authority [32]byte
	// Active is false while the issuer is suspended.
	Active    bool
	CreatedAt time.Time
}

// CredentialState is the registry's status of a credential.
type CredentialState uint8

const (
	CredentialActive  CredentialState = 0
	CredentialRevoked CredentialState = 1
)

// CredentialStatus is the registry's record of one issued credential. It says
// nothing about what the credential attests.
type CredentialStatus struct {
	// Ref identifies the credential; see the CredentialRef function.
	Ref [32]byte
	// IssuerID is the issuer that registered the credential.
	IssuerID  [32]byte
	State     CredentialState
	ExpiresAt time.Time
}

// WriteResult reports the outcome of a write to the registry.
type WriteResult struct {
	// Changed is false when the registry already held the requested state; then
	// nothing was written and Reference is empty.
	Changed bool
	// Reference identifies the ledger entry that recorded the change (for
	// Solana, the transaction signature). It is empty when nothing was written
	// or the write's outcome is unknown.
	Reference string
}

// IssuerID maps a credential issuer identifier (the "iss" claim) to the
// 32-byte issuer id used in the registry. Issuer identifiers are public, so a
// plain domain-separated hash is sufficient.
func IssuerID(issuer string) [32]byte {
	return sha256.Sum256([]byte("credential-registry/issuer/v1\x00" + issuer))
}

// CredentialRef maps a credential's random id (the "jti" claim) to the opaque
// 32-byte credential reference used in the registry. The credential id is an
// unguessable random value, so the reference reveals nothing about the subject
// and cannot be linked to a credential by anyone who does not hold it.
func CredentialRef(credentialID string) [32]byte {
	return sha256.Sum256([]byte("credential-registry/credential/v1\x00" + credentialID))
}
