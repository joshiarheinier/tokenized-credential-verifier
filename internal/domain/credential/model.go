// Package credential defines the signed credential: its data model, signing
// and verification. It is independent of what a credential attests: credential
// types (KYC status, a ticket, a membership, ...) are described by a Schema and
// registered in a Schemas set. It is pure domain code: it has no dependency on
// the blockchain, HTTP or any other infrastructure. On-chain registration and
// status checks are the application layer's concern.
//
// Format: a compact JWS (RFC 7515) with alg=EdDSA (Ed25519), carrying a
// JWT-style claim set. It follows the shape of a W3C Verifiable Credential but
// makes no claim of W3C conformance; see docs/td_init_project.md section 4.1.
package credential

import "errors"

const (
	// FormatVersion is the credential format version carried in the "ver" claim.
	FormatVersion = 1
	// AlgEdDSA is the only accepted signature algorithm.
	AlgEdDSA = "EdDSA"
	// MaxTokenSize bounds the size of a credential accepted for verification.
	MaxTokenSize = 8 * 1024
)

// Claims is the credential payload. Attributes holds the type-specific facts
// (the "claims" member); their shape is defined by the credential type's Schema.
type Claims struct {
	Version        int            `json:"ver"`
	Issuer         string         `json:"iss"`
	Subject        string         `json:"sub"`
	ID             string         `json:"jti"`
	IssuedAt       int64          `json:"iat"`
	ExpiresAt      int64          `json:"exp"`
	CredentialType string         `json:"credential_type"`
	Attributes     map[string]any `json:"claims"`
}

// Approval is an issuer's decision to issue a credential of CredentialType to
// Subject with the given claims. In production it comes from the issuer's own
// process (an identity check, a ticket purchase, a membership signup); in local
// development it is simulated.
type Approval struct {
	Subject        string
	CredentialType string
	Claims         map[string]any
}

// Verification failures. Callers use errors.Is to classify them.
var (
	ErrMalformed          = errors.New("credential: malformed")
	ErrUnsupportedAlg     = errors.New("credential: unsupported algorithm")
	ErrUnsupportedVersion = errors.New("credential: unsupported version")
	ErrUnsupportedType    = errors.New("credential: unsupported credential type")
	ErrUnknownIssuer      = errors.New("credential: unknown issuer key")
	ErrInvalidSignature   = errors.New("credential: invalid signature")
	ErrExpired            = errors.New("credential: expired")
	ErrNotYetValid        = errors.New("credential: not yet valid")
)
