package verification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
	domainverification "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/verification"
	"github.com/joshiarheinier/tokenized-credential-verifier/pkg/connector/blockchain"
)

var now = time.Unix(1_793_000_000, 0)

const (
	issuerName = "did:example:issuer"
	credID     = "cred-1"

	// A made-up credential type: verification must work for any registered
	// type, not just KYC.
	testType = "Membership"
)

var testSchemas = func() *credential.Schemas {
	s, err := credential.NewSchemas(credential.Schema{
		Type: testType,
		Fields: []credential.Field{
			{Name: "tier", Kind: credential.String, Required: true},
			{Name: "active", Kind: credential.Bool, Required: true},
		},
	})
	if err != nil {
		panic(err)
	}
	return s
}()

// testPolicies accepts active memberships.
var testPolicies = []domainverification.Policy{{
	CredentialType: testType,
	Require:        []domainverification.Requirement{{Claim: "active", Equals: true}},
}}

type fakeBlockchainClient struct {
	issuer    blockchain.IssuerRecord
	issuerErr error
	status    blockchain.CredentialStatus
	statusErr error
}

func (f *fakeBlockchainClient) GetIssuer(_ context.Context, id [32]byte) (blockchain.IssuerRecord, error) {
	return f.issuer, f.issuerErr
}

func (f *fakeBlockchainClient) GetCredentialStatus(_ context.Context, ref [32]byte) (blockchain.CredentialStatus, error) {
	return f.status, f.statusErr
}

type fixture struct {
	svc   *Service
	token string
	reg   *fakeBlockchainClient
	pub   ed25519.PublicKey
}

// newFixture issues a credential and returns a service whose registry holds a
// healthy issuer and an active credential; tests then break one thing.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := credential.NewSigner(issuerName, priv)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(credential.Claims{
		Subject:        "did:example:user",
		ID:             credID,
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(time.Hour).Unix(),
		CredentialType: testType,
		Attributes:     map[string]any{"tier": "gold", "active": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	v := credential.NewVerifier(testSchemas, func() time.Time { return now })
	v.Trust(issuerName, pub)

	issuerID := blockchain.IssuerID(issuerName)
	reg := &fakeBlockchainClient{
		issuer: blockchain.IssuerRecord{IssuerID: issuerID, SigningKey: pub, Active: true},
		status: blockchain.CredentialStatus{
			Ref:       blockchain.CredentialRef(credID),
			IssuerID:  issuerID,
			State:     blockchain.CredentialActive,
			ExpiresAt: now.Add(time.Hour),
		},
	}
	svc := NewService(v, testPolicies, WithBlockchainClient(reg), WithClock(func() time.Time { return now }))
	return &fixture{svc: svc, token: token, reg: reg, pub: pub}
}

func (f *fixture) verify() Result { return f.svc.Verify(context.Background(), f.token) }

func TestChainBackedVerificationAcceptsHealthyCredential(t *testing.T) {
	f := newFixture(t)
	if res := f.verify(); !res.Valid {
		t.Fatalf("Valid = false (%s), want true", res.Reason)
	}
}

func TestChainRejections(t *testing.T) {
	otherKey, _, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name   string
		break_ func(*fakeBlockchainClient)
		want   Reason
	}{
		{"issuer not registered", func(r *fakeBlockchainClient) { r.issuerErr = blockchain.ErrNotFound }, ReasonUntrustedIssuer},
		{"issuer suspended", func(r *fakeBlockchainClient) { r.issuer.Active = false }, ReasonUntrustedIssuer},
		{"registry attests a different signing key", func(r *fakeBlockchainClient) { r.issuer.SigningKey = otherKey }, ReasonUntrustedIssuer},
		{"credential not registered", func(r *fakeBlockchainClient) { r.statusErr = blockchain.ErrNotFound }, ReasonNotRegistered},
		{"credential registered by another issuer", func(r *fakeBlockchainClient) { r.status.IssuerID = blockchain.IssuerID("other") }, ReasonNotRegistered},
		{"credential revoked", func(r *fakeBlockchainClient) { r.status.State = blockchain.CredentialRevoked }, ReasonRevoked},
		{"credential expired on chain", func(r *fakeBlockchainClient) { r.status.ExpiresAt = now }, ReasonExpired},
		{"unknown on-chain state", func(r *fakeBlockchainClient) { r.status.State = 9 }, ReasonUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.break_(f.reg)
			res := f.verify()
			if res.Valid || res.Reason != tc.want {
				t.Fatalf("Valid=%v Reason=%q, want rejected with %q", res.Valid, res.Reason, tc.want)
			}
			if len(res.Claims) != 0 || res.Issuer != "" {
				t.Fatalf("rejected result leaked claims: %+v", res)
			}
		})
	}
}

// Anything other than a definite "not found" must fail closed as unavailable,
// never be read as a verdict on the credential and never be accepted.
func TestVerificationFailsClosedWhenChainCannotBeRead(t *testing.T) {
	for name, errs := range map[string]error{
		"rpc unavailable":   blockchain.ErrUnavailable,
		"invalid account":   blockchain.ErrInvalidAccount,
		"arbitrary failure": errors.New("boom"),
		"context deadline":  context.DeadlineExceeded,
	} {
		t.Run("issuer/"+name, func(t *testing.T) {
			f := newFixture(t)
			f.reg.issuerErr = errs
			if res := f.verify(); res.Valid || res.Reason != ReasonUnavailable {
				t.Fatalf("Valid=%v Reason=%q, want rejected as unavailable", res.Valid, res.Reason)
			}
		})
		t.Run("status/"+name, func(t *testing.T) {
			f := newFixture(t)
			f.reg.statusErr = errs
			if res := f.verify(); res.Valid || res.Reason != ReasonUnavailable {
				t.Fatalf("Valid=%v Reason=%q, want rejected as unavailable", res.Valid, res.Reason)
			}
		})
	}
}

func TestLocalFailuresDoNotConsultTheChain(t *testing.T) {
	f := newFixture(t)
	f.reg.issuerErr = blockchain.ErrUnavailable // would turn into "unavailable" if consulted
	f.token = f.token[:len(f.token)-4] + "AAAA" // corrupt the signature
	if res := f.verify(); res.Reason != ReasonInvalidSignature {
		t.Fatalf("Reason = %q, want invalid_signature", res.Reason)
	}
}

func TestWithoutRegistryOnlyLocalChecksApply(t *testing.T) {
	f := newFixture(t)
	f.reg.issuerErr = blockchain.ErrUnavailable
	svc := NewService(credentialVerifier(t, f), testPolicies)
	if res := svc.Verify(context.Background(), f.token); !res.Valid {
		t.Fatalf("Valid = false (%s), want true without a registry", res.Reason)
	}
}

func credentialVerifier(t *testing.T, f *fixture) *credential.Verifier {
	t.Helper()
	v := credential.NewVerifier(testSchemas, func() time.Time { return now })
	v.Trust(issuerName, f.pub)
	return v
}
