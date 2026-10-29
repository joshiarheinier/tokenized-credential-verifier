package credential

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var b64 = base64.RawURLEncoding.Strict()

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// KeyID derives a stable key identifier from an Ed25519 public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return b64.EncodeToString(sum[:12])
}

// Signer signs credentials with a dedicated issuer key. This key is separate
// from any Solana transaction-signing key.
type Signer struct {
	issuerID string
	key      ed25519.PrivateKey
	kid      string
}

// NewSigner returns a Signer for issuerID using key.
func NewSigner(issuerID string, key ed25519.PrivateKey) (*Signer, error) {
	if issuerID == "" {
		return nil, errors.New("credential: issuer id is required")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("credential: invalid Ed25519 private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	return &Signer{issuerID: issuerID, key: key, kid: KeyID(pub)}, nil
}

// IssuerID returns the issuer identifier placed in the "iss" claim.
func (s *Signer) IssuerID() string { return s.issuerID }

// PublicKey returns the verification key matching the signing key.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// Sign serialises claims and returns the compact signed credential. The
// claims' issuer and version are forced to the signer's own values.
func (s *Signer) Sign(c Claims) (string, error) {
	c.Issuer = s.issuerID
	c.Version = FormatVersion

	h, err := json.Marshal(header{Alg: AlgEdDSA, Typ: "JWT", Kid: s.kid})
	if err != nil {
		return "", fmt.Errorf("credential: marshal header: %w", err)
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("credential: marshal claims: %w", err)
	}
	signingInput := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(s.key, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), nil
}
