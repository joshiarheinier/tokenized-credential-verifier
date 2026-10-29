// Package issuer manages the credential issuer's identity and signing key.
package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/credential"
)

var seedEncoding = base64.RawURLEncoding.Strict()

// Issuer is the issuer identity with its signing capability.
type Issuer struct {
	ID     string
	Signer *credential.Signer
}

// GenerateSeed returns a fresh random Ed25519 seed, base64url-encoded, in the
// format accepted by New.
func GenerateSeed() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("issuer: generate seed: %w", err)
	}
	return seedEncoding.EncodeToString(seed), nil
}

// New builds an Issuer from a base64url-encoded 32-byte Ed25519 seed.
func New(id, seed string) (*Issuer, error) {
	raw, err := seedEncoding.DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		// Do not include the seed in the error.
		return nil, fmt.Errorf("issuer: signing key seed must be %d bytes, base64url without padding", ed25519.SeedSize)
	}
	signer, err := credential.NewSigner(id, ed25519.NewKeyFromSeed(raw))
	if err != nil {
		return nil, err
	}
	return &Issuer{ID: id, Signer: signer}, nil
}
