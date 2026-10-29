package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/pkg/connector/blockchain"
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

type fakeApprovals struct {
	approval Approval
	err      error
	calls    int
}

func (f *fakeApprovals) ConsumeApproval(context.Context, string) (Approval, error) {
	f.calls++
	return f.approval, f.err
}

func TestServiceIssueFromApproval(t *testing.T) {
	s := newSigner(t)
	src := &fakeApprovals{approval: Approval{Subject: "user-1", CredentialType: testType, Claims: map[string]any{"tier": "gold", "vip": false}}}
	svc, err := NewService(s, src, testSchemas, 24*time.Hour, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueFromApproval(context.Background(), "approval-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := fixedNow.Add(24 * time.Hour).UTC(); !issued.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", issued.ExpiresAt, want)
	}
	c, err := verifierTrusting(s, fixedNow).Verify(issued.Token)
	if err != nil {
		t.Fatalf("issued credential does not verify: %v", err)
	}
	if c.Subject != "user-1" || c.CredentialType != testType || c.Attributes["tier"] != "gold" || c.Attributes["vip"] != false || c.ID == "" {
		t.Errorf("claims = %+v", c)
	}

	second, _ := svc.IssueFromApproval(context.Background(), "approval-1")
	c2, _ := verifierTrusting(s, fixedNow).Verify(second.Token)
	if c.ID == c2.ID {
		t.Error("credential ids are not unique")
	}
}

func TestServicePropagatesApprovalErrors(t *testing.T) {
	sentinel := errors.New("not approved")
	svc, _ := NewService(newSigner(t), &fakeApprovals{err: sentinel}, testSchemas, time.Hour, nil)
	if _, err := svc.IssueFromApproval(context.Background(), "x"); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}

func TestNewServiceValidation(t *testing.T) {
	s := newSigner(t)
	if _, err := NewService(nil, &fakeApprovals{}, testSchemas, time.Hour, nil); err == nil {
		t.Error("nil signer accepted")
	}
	if _, err := NewService(s, nil, testSchemas, time.Hour, nil); err == nil {
		t.Error("nil approvals accepted")
	}
	if _, err := NewService(s, &fakeApprovals{}, nil, time.Hour, nil); err == nil {
		t.Error("nil schemas accepted")
	}
	if _, err := NewService(s, &fakeApprovals{}, testSchemas, 0, nil); err == nil {
		t.Error("zero ttl accepted")
	}
}

type registerCall struct {
	issuerID, ref [32]byte
	exp           time.Time
}

type fakeBlockchainClient struct {
	err   error
	calls []registerCall
}

func (f *fakeBlockchainClient) RegisterCredential(_ context.Context, issuerID, ref [32]byte, exp time.Time) (blockchain.WriteResult, error) {
	f.calls = append(f.calls, registerCall{issuerID, ref, exp})
	return blockchain.WriteResult{}, f.err
}

func TestServiceRegistersCredentialBeforeReturningIt(t *testing.T) {
	s := newSigner(t)
	reg := &fakeBlockchainClient{}
	src := &fakeApprovals{approval: Approval{Subject: "user-1", CredentialType: testType, Claims: map[string]any{"tier": "gold", "vip": true}}}
	svc, _ := NewService(s, src, testSchemas, time.Hour, func() time.Time { return fixedNow }, WithBlockchainClient(reg))

	issued, err := svc.IssueFromApproval(context.Background(), "approval-1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := verifierTrusting(s, fixedNow).Verify(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.calls) != 1 {
		t.Fatalf("blockchain calls = %d, want 1", len(reg.calls))
	}
	got := reg.calls[0]
	if got.issuerID != blockchain.IssuerID(s.IssuerID()) ||
		got.ref != blockchain.CredentialRef(c.ID) ||
		!got.exp.Equal(time.Unix(c.ExpiresAt, 0)) {
		t.Errorf("registered %+v, want the ids and expiry of the issued credential", got)
	}
}

func TestServiceReturnsNoCredentialWhenRegistrationFails(t *testing.T) {
	boom := errors.New("chain down")
	src := &fakeApprovals{approval: Approval{Subject: "user-1", CredentialType: testType, Claims: map[string]any{"tier": "gold", "vip": true}}}
	svc, _ := NewService(newSigner(t), src, testSchemas, time.Hour, nil, WithBlockchainClient(&fakeBlockchainClient{err: boom}))

	issued, err := svc.IssueFromApproval(context.Background(), "approval-1")
	if !errors.Is(err, boom) || issued.Token != "" {
		t.Fatalf("issued=%+v err=%v, want no credential and the blockchain error", issued, err)
	}
}

func TestServiceDoesNotRegisterForInvalidApprovals(t *testing.T) {
	reg := &fakeBlockchainClient{}
	svc, _ := NewService(newSigner(t), &fakeApprovals{err: errors.New("not approved")}, testSchemas, time.Hour, nil, WithBlockchainClient(reg))
	if _, err := svc.IssueFromApproval(context.Background(), "x"); err == nil {
		t.Fatal("want error")
	}
	if len(reg.calls) != 0 {
		t.Fatal("an invalid approval must not trigger an on-chain registration")
	}
}
