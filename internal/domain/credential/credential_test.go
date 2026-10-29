package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Unix(1_793_000_000, 0)

// The credential package knows nothing about any particular credential type;
// these tests use a made-up one to prove it.
const testType = "TestPass"

var testSchemas = mustSchemas(Schema{
	Type: testType,
	Fields: []Field{
		{Name: "tier", Kind: String, Required: true},
		{Name: "vip", Kind: Bool, Required: true},
		{Name: "seats", Kind: Number},
	},
})

func mustSchemas(s ...Schema) *Schemas {
	set, err := NewSchemas(s...)
	if err != nil {
		panic(err)
	}
	return set
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func newSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner("did:example:issuer", newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validClaims() Claims {
	return Claims{
		Subject:        "did:example:user-123",
		ID:             "cred-1",
		IssuedAt:       fixedNow.Unix(),
		ExpiresAt:      fixedNow.Add(time.Hour).Unix(),
		CredentialType: testType,
		Attributes:     map[string]any{"tier": "gold", "vip": true},
	}
}

func verifierTrusting(s *Signer, now time.Time) *Verifier {
	v := NewVerifier(testSchemas, func() time.Time { return now })
	v.Trust(s.IssuerID(), s.PublicKey())
	return v
}

// resign signs arbitrary header/payload JSON with key, bypassing Signer so
// tests can craft hostile tokens.
func craft(t *testing.T, key ed25519.PrivateKey, header, payload string) string {
	t.Helper()
	in := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	return in + "." + b64.EncodeToString(ed25519.Sign(key, []byte(in)))
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := newSigner(t)
	token, err := s.Sign(validClaims())
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifierTrusting(s, fixedNow).Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := validClaims()
	want.Issuer, want.Version = s.IssuerID(), FormatVersion
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("claims = %+v, want %+v", *got, want)
	}
}

func TestSignOverridesIssuerAndVersion(t *testing.T) {
	s := newSigner(t)
	c := validClaims()
	c.Issuer, c.Version = "did:example:someone-else", 99
	token, _ := s.Sign(c)
	got, err := verifierTrusting(s, fixedNow).Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != s.IssuerID() || got.Version != FormatVersion {
		t.Errorf("issuer/version = %q/%d", got.Issuer, got.Version)
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	s := newSigner(t)
	token, _ := s.Sign(validClaims())
	parts := strings.Split(token, ".")

	raw, _ := b64.DecodeString(parts[1])
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["claims"].(map[string]any)["tier"] = "silver"
	forged, _ := json.Marshal(m)

	tampered := parts[0] + "." + b64.EncodeToString(forged) + "." + parts[2]
	_, err := verifierTrusting(s, fixedNow).Verify(tampered)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestTamperedSignatureFails(t *testing.T) {
	s := newSigner(t)
	token, _ := s.Sign(validClaims())
	parts := strings.Split(token, ".")
	sig, _ := b64.DecodeString(parts[2])
	sig[0] ^= 0xff
	_, err := verifierTrusting(s, fixedNow).Verify(parts[0] + "." + parts[1] + "." + b64.EncodeToString(sig))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestExpiredAndNotYetValid(t *testing.T) {
	s := newSigner(t)
	token, _ := s.Sign(validClaims())

	exp := validClaims().ExpiresAt
	for name, tc := range map[string]struct {
		now  time.Time
		want error
	}{
		"one second before expiry": {time.Unix(exp-1, 0), nil},
		"exactly at expiry":        {time.Unix(exp, 0), ErrExpired},
		"long after expiry":        {time.Unix(exp, 0).Add(24 * time.Hour), ErrExpired},
		"before issuance":          {fixedNow.Add(-time.Minute), ErrNotYetValid},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := verifierTrusting(s, tc.now).Verify(token)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	trusted := newSigner(t)
	attacker, _ := NewSigner(trusted.IssuerID(), newKey(t)) // same issuer id, different key
	token, _ := attacker.Sign(validClaims())
	_, err := verifierTrusting(trusted, fixedNow).Verify(token)
	if !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("err = %v, want ErrUnknownIssuer", err)
	}
}

func TestKeyIssuerMismatchRejected(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(testSchemas, func() time.Time { return fixedNow })
	v.Trust("did:example:other", s.PublicKey()) // key trusted only for a different issuer
	token, _ := s.Sign(validClaims())
	if _, err := v.Verify(token); !errors.Is(err, ErrUnknownIssuer) {
		t.Fatalf("err = %v, want ErrUnknownIssuer", err)
	}
}

func TestUnsupportedAlgorithmsRejected(t *testing.T) {
	s := newSigner(t)
	key := newKey(t)
	kid := KeyID(s.PublicKey())
	payload := `{"ver":1}`
	v := verifierTrusting(s, fixedNow)

	for _, alg := range []string{"none", "HS256", "RS256", "eddsa", ""} {
		token := craft(t, key, `{"alg":"`+alg+`","typ":"JWT","kid":"`+kid+`"}`, payload)
		if _, err := v.Verify(token); !errors.Is(err, ErrUnsupportedAlg) {
			t.Errorf("alg %q: err = %v, want ErrUnsupportedAlg", alg, err)
		}
	}
	// "none" with an empty signature segment.
	none := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"`+kid+`"}`)) + "." + b64.EncodeToString([]byte(payload)) + "."
	if _, err := v.Verify(none); !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("unsigned token: err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestMalformedInputsRejected(t *testing.T) {
	s := newSigner(t)
	v := verifierTrusting(s, fixedNow)
	good, _ := s.Sign(validClaims())
	parts := strings.Split(good, ".")

	for name, token := range map[string]string{
		"empty":            "",
		"one segment":      "abc",
		"two segments":     "a.b",
		"four segments":    good + ".x",
		"not base64":       "!!!.!!!.!!!",
		"padded base64":    parts[0] + "=." + parts[1] + "." + parts[2],
		"header not json":  b64.EncodeToString([]byte("nope")) + "." + parts[1] + "." + parts[2],
		"header extra key": craft(t, newKey(t), `{"alg":"EdDSA","typ":"JWT","kid":"x","jku":"http://evil"}`, `{}`),
		"oversized":        strings.Repeat("a", MaxTokenSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(token); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestSignedButInvalidClaimsRejected(t *testing.T) {
	s := newSigner(t)
	v := verifierTrusting(s, fixedNow)
	hdr := `{"alg":"EdDSA","typ":"JWT","kid":"` + KeyID(s.PublicKey()) + `"}`
	// Signed by the real key, so only claim validation can reject these.
	key := s.key

	base := func(mut func(c *Claims)) string {
		c := validClaims()
		c.Issuer, c.Version = s.IssuerID(), FormatVersion
		mut(&c)
		p, _ := json.Marshal(c)
		return craft(t, key, hdr, string(p))
	}
	for name, tc := range map[string]struct {
		token string
		want  error
	}{
		"wrong version":  {base(func(c *Claims) { c.Version = 2 }), ErrUnsupportedVersion},
		"wrong type":     {base(func(c *Claims) { c.CredentialType = "Other" }), ErrUnsupportedType},
		"missing claim":  {base(func(c *Claims) { c.Attributes = map[string]any{"tier": "gold"} }), ErrInvalidClaims},
		"wrong kind":     {base(func(c *Claims) { c.Attributes = map[string]any{"tier": 1, "vip": true} }), ErrInvalidClaims},
		"extra claim":    {base(func(c *Claims) { c.Attributes = map[string]any{"tier": "gold", "vip": true, "name": "Ada"} }), ErrInvalidClaims},
		"no claims":      {base(func(c *Claims) { c.Attributes = nil }), ErrMalformed},
		"wrong issuer":   {base(func(c *Claims) { c.Issuer = "did:example:evil" }), ErrUnknownIssuer},
		"missing jti":    {base(func(c *Claims) { c.ID = "" }), ErrMalformed},
		"missing sub":    {base(func(c *Claims) { c.Subject = "" }), ErrMalformed},
		"missing exp":    {base(func(c *Claims) { c.ExpiresAt = 0 }), ErrMalformed},
		"unknown claims": {craft(t, key, hdr, `{"ver":1,"admin":true}`), ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify(tc.token); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewSignerValidation(t *testing.T) {
	if _, err := NewSigner("", newKey(t)); err == nil {
		t.Error("empty issuer id accepted")
	}
	if _, err := NewSigner("did:example:i", ed25519.PrivateKey("short")); err == nil {
		t.Error("short key accepted")
	}
}
