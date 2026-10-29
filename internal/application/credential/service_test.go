package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	domaincredential "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
)

const testType = "TestPass"

var fixedNow = time.Unix(1_793_000_000, 0)

var testSchemas = func() *domaincredential.Schemas {
	schemas, err := domaincredential.NewSchemas(domaincredential.Schema{
		Type: testType,
		Fields: []domaincredential.Field{
			{Name: "tier", Kind: domaincredential.String, Required: true},
			{Name: "vip", Kind: domaincredential.Bool, Required: true},
			{Name: "seats", Kind: domaincredential.Number},
		},
	})
	if err != nil {
		panic(err)
	}
	return schemas
}()

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newSigner(t *testing.T) *domaincredential.Signer {
	t.Helper()

	signer, err := domaincredential.NewSigner("did:example:issuer", newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func verifierTrusting(signer *domaincredential.Signer, now time.Time) *domaincredential.Verifier {
	verifier := domaincredential.NewVerifier(testSchemas, func() time.Time { return now })
	verifier.Trust(signer.IssuerID(), signer.PublicKey())
	return verifier
}

type fakeApprovals struct {
	approval domaincredential.Approval
	err      error
	calls    int
}

func (f *fakeApprovals) ConsumeApproval(context.Context, string) (domaincredential.Approval, error) {
	f.calls++
	return f.approval, f.err
}

type registerCall struct {
	issuerID [32]byte
	ref      [32]byte
	exp      time.Time
}

type fakeBlockchainClient struct {
	err   error
	calls []registerCall
}

func (f *fakeBlockchainClient) RegisterCredential(
	_ context.Context,
	issuerID, ref [32]byte,
	expiresAt time.Time,
) (blockchain.WriteResult, error) {
	f.calls = append(f.calls, registerCall{
		issuerID: issuerID,
		ref:      ref,
		exp:      expiresAt,
	})
	return blockchain.WriteResult{}, f.err
}

func TestServiceIssueFromApproval(t *testing.T) {
	signer := newSigner(t)
	approvals := &fakeApprovals{
		approval: domaincredential.Approval{
			Subject:        "user-1",
			CredentialType: testType,
			Claims:         map[string]any{"tier": "gold", "vip": false},
		},
	}

	service, err := NewService(signer, approvals, testSchemas, 24*time.Hour, func() time.Time {
		return fixedNow
	})
	if err != nil {
		t.Fatal(err)
	}

	issued, err := service.IssueFromApproval(context.Background(), "approval-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := fixedNow.Add(24 * time.Hour).UTC(); !issued.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", issued.ExpiresAt, want)
	}

	claims, err := verifierTrusting(signer, fixedNow).Verify(issued.Token)
	if err != nil {
		t.Fatalf("issued credential does not verify: %v", err)
	}
	if claims.Subject != "user-1" ||
		claims.CredentialType != testType ||
		claims.Attributes["tier"] != "gold" ||
		claims.Attributes["vip"] != false ||
		claims.ID == "" {
		t.Errorf("claims = %+v", claims)
	}

	second, err := service.IssueFromApproval(context.Background(), "approval-1")
	if err != nil {
		t.Fatal(err)
	}
	secondClaims, err := verifierTrusting(signer, fixedNow).Verify(second.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ID == secondClaims.ID {
		t.Error("credential IDs are not unique")
	}
}

func TestServicePropagatesApprovalErrors(t *testing.T) {
	wantErr := errors.New("not approved")
	service, err := NewService(
		newSigner(t),
		&fakeApprovals{err: wantErr},
		testSchemas,
		time.Hour,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.IssueFromApproval(context.Background(), "approval-1"); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func TestNewServiceValidation(t *testing.T) {
	signer := newSigner(t)
	approvals := &fakeApprovals{}

	tests := []struct {
		name      string
		signer    *domaincredential.Signer
		approvals ApprovalSource
		schemas   *domaincredential.Schemas
		ttl       time.Duration
	}{
		{name: "nil signer", signer: nil, approvals: approvals, schemas: testSchemas, ttl: time.Hour},
		{name: "nil approvals", signer: signer, approvals: nil, schemas: testSchemas, ttl: time.Hour},
		{name: "nil schemas", signer: signer, approvals: approvals, schemas: nil, ttl: time.Hour},
		{name: "zero TTL", signer: signer, approvals: approvals, schemas: testSchemas, ttl: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewService(tt.signer, tt.approvals, tt.schemas, tt.ttl, nil); err == nil {
				t.Fatal("NewService returned no error")
			}
		})
	}
}

func TestServiceRegistersCredentialBeforeReturningIt(t *testing.T) {
	signer := newSigner(t)
	registry := &fakeBlockchainClient{}
	approvals := &fakeApprovals{
		approval: domaincredential.Approval{
			Subject:        "user-1",
			CredentialType: testType,
			Claims:         map[string]any{"tier": "gold", "vip": true},
		},
	}
	service, err := NewService(
		signer,
		approvals,
		testSchemas,
		time.Hour,
		func() time.Time { return fixedNow },
		WithBlockchainClient(registry),
	)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := service.IssueFromApproval(context.Background(), "approval-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifierTrusting(signer, fixedNow).Verify(issued.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.calls) != 1 {
		t.Fatalf("blockchain calls = %d, want 1", len(registry.calls))
	}

	got := registry.calls[0]
	if got.issuerID != blockchain.IssuerID(signer.IssuerID()) ||
		got.ref != blockchain.CredentialRef(claims.ID) ||
		!got.exp.Equal(time.Unix(claims.ExpiresAt, 0)) {
		t.Errorf("registered %+v, want IDs and expiry of issued credential", got)
	}
}

func TestServiceReturnsNoCredentialWhenRegistrationFails(t *testing.T) {
	wantErr := errors.New("chain down")
	approvals := &fakeApprovals{
		approval: domaincredential.Approval{
			Subject:        "user-1",
			CredentialType: testType,
			Claims:         map[string]any{"tier": "gold", "vip": true},
		},
	}
	service, err := NewService(
		newSigner(t),
		approvals,
		testSchemas,
		time.Hour,
		nil,
		WithBlockchainClient(&fakeBlockchainClient{err: wantErr}),
	)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := service.IssueFromApproval(context.Background(), "approval-1")
	if !errors.Is(err, wantErr) || issued.Token != "" {
		t.Fatalf("issued = %+v, error = %v; want no credential and blockchain error", issued, err)
	}
}

func TestServiceDoesNotRegisterForInvalidApprovals(t *testing.T) {
	registry := &fakeBlockchainClient{}
	service, err := NewService(
		newSigner(t),
		&fakeApprovals{err: errors.New("not approved")},
		testSchemas,
		time.Hour,
		nil,
		WithBlockchainClient(registry),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.IssueFromApproval(context.Background(), "approval-1"); err == nil {
		t.Fatal("IssueFromApproval returned no error")
	}
	if len(registry.calls) != 0 {
		t.Fatal("invalid approval triggered on-chain registration")
	}
}

func TestServiceRejectsApprovalsThatDoNotMatchTheirType(t *testing.T) {
	registry := &fakeBlockchainClient{}
	invalidApprovals := map[string]domaincredential.Approval{
		"unknown type": {
			Subject:        "user-1",
			CredentialType: "Unknown",
			Claims:         map[string]any{"tier": "gold", "vip": true},
		},
		"claims mismatch": {
			Subject:        "user-1",
			CredentialType: testType,
			Claims:         map[string]any{"tier": "gold"},
		},
		"unexpected claim": {
			Subject:        "user-1",
			CredentialType: testType,
			Claims:         map[string]any{"tier": "gold", "vip": true, "ssn": "x"},
		},
	}

	for name, approval := range invalidApprovals {
		t.Run(name, func(t *testing.T) {
			service, err := NewService(
				newSigner(t),
				&fakeApprovals{approval: approval},
				testSchemas,
				time.Hour,
				nil,
				WithBlockchainClient(registry),
			)
			if err != nil {
				t.Fatal(err)
			}

			issued, err := service.IssueFromApproval(context.Background(), "approval-1")
			if err == nil || issued.Token != "" {
				t.Errorf("issued = %+v, error = %v; want refusal", issued, err)
			}
		})
	}

	if len(registry.calls) != 0 {
		t.Fatal("invalid approvals must not be registered on chain")
	}
}
