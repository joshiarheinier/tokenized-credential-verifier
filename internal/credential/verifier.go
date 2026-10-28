package credential

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type trustedKey struct {
	issuer string
	key    ed25519.PublicKey
}

// Verifier checks the signature and validity period of credentials against a
// fixed set of trusted issuer keys. It does not consult the blockchain; issuer
// trust on Solana is layered on top in a later phase.
type Verifier struct {
	keys map[string]trustedKey // by key id
	now  func() time.Time
}

// NewVerifier returns a Verifier with no trusted keys. now may be nil to use
// the wall clock.
func NewVerifier(now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{keys: make(map[string]trustedKey), now: now}
}

// Trust adds an issuer's verification key.
func (v *Verifier) Trust(issuerID string, pub ed25519.PublicKey) {
	v.keys[KeyID(pub)] = trustedKey{issuer: issuerID, key: pub}
}

// Verify parses and validates a compact credential. It never returns claims
// for a credential that failed any check. Errors wrap one of the Err*
// sentinels.
func (v *Verifier) Verify(token string) (*Claims, error) {
	c, _, err := v.VerifyWithKey(token)
	return c, err
}

// VerifyWithKey is Verify that also returns the public key the signature was
// verified with, so callers can check it against an independent source of
// issuer trust such as the on-chain registry.
func (v *Verifier) VerifyWithKey(token string) (*Claims, ed25519.PublicKey, error) {
	if len(token) > MaxTokenSize {
		return nil, nil, fmt.Errorf("%w: too large", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("%w: want 3 segments", ErrMalformed)
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	rawPayload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}

	var h header
	if err := decodeStrict(rawHeader, &h); err != nil {
		return nil, nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	// Reject anything but EdDSA, including "none", before touching keys.
	if h.Alg != AlgEdDSA {
		return nil, nil, ErrUnsupportedAlg
	}
	tk, ok := v.keys[h.Kid]
	if !ok {
		return nil, nil, ErrUnknownIssuer
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(tk.key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, nil, ErrInvalidSignature
	}

	// Only now is the payload authenticated and safe to interpret.
	var c Claims
	if err := decodeStrict(rawPayload, &c); err != nil {
		return nil, nil, fmt.Errorf("%w: claims: %v", ErrMalformed, err)
	}
	if c.Version != FormatVersion {
		return nil, nil, ErrUnsupportedVersion
	}
	if c.Issuer != tk.issuer {
		return nil, nil, ErrUnknownIssuer
	}
	if c.CredentialType != TypeKYCStatus {
		return nil, nil, ErrUnsupportedType
	}
	if c.ID == "" || c.Subject == "" || c.ExpiresAt == 0 {
		return nil, nil, fmt.Errorf("%w: missing required claim", ErrMalformed)
	}
	now := v.now().Unix()
	if now >= c.ExpiresAt {
		return nil, nil, ErrExpired
	}
	if c.IssuedAt > now {
		return nil, nil, ErrNotYetValid
	}
	return &c, tk.key, nil
}

// decodeStrict unmarshals a single JSON object, rejecting unknown fields and
// trailing data.
func decodeStrict(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}
