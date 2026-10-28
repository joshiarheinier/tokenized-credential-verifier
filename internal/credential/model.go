// Package credential defines the signed KYC credential: its data model,
// signing and verification. Signing and verification never touch the
// blockchain; only the optional on-chain registration at issuance does, through
// the BlockchainClient interface.
//
// Format: a compact JWS (RFC 7515) with alg=EdDSA (Ed25519), carrying a
// JWT-style claim set. It follows the shape of a W3C Verifiable Credential but
// makes no claim of W3C conformance; see docs/td_init_project.md section 4.1.
package credential

import "errors"

const (
	// FormatVersion is the credential format version carried in the "ver" claim.
	FormatVersion = 1
	// TypeKYCStatus is the only credential type supported so far.
	TypeKYCStatus = "KYCStatus"
	// AlgEdDSA is the only accepted signature algorithm.
	AlgEdDSA = "EdDSA"
	// MaxTokenSize bounds the size of a credential accepted for verification.
	MaxTokenSize = 8 * 1024
)

// Claims is the credential payload.
type Claims struct {
	Version        int       `json:"ver"`
	Issuer         string    `json:"iss"`
	Subject        string    `json:"sub"`
	ID             string    `json:"jti"`
	IssuedAt       int64     `json:"iat"`
	ExpiresAt      int64     `json:"exp"`
	CredentialType string    `json:"credential_type"`
	KYC            KYCClaims `json:"claims"`
}

// KYCClaims are the attested identity facts. They are deliberately coarse:
// no name, birthdate, address or document data.
type KYCClaims struct {
	KYCVerified bool   `json:"kyc_verified"`
	Over18      bool   `json:"over_18"`
	Country     string `json:"country"`
}

// Approval is a simulated KYC approval that may be turned into a credential.
type Approval struct {
	Subject string
	Claims  KYCClaims
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
