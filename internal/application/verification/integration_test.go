//go:build integration

package verification_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/verification"
	domaincredential "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential/kyc"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
	domainverification "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/verification"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/testutil"
)

var schemas = func() *domaincredential.Schemas {
	s, err := domaincredential.NewSchemas(kyc.Schema)
	if err != nil {
		panic(err)
	}
	return s
}()

var policies = []domainverification.Policy{{
	CredentialType: kyc.Type,
	Require:        []domainverification.Requirement{{Claim: kyc.ClaimVerified, Equals: true}},
}}

type approvals struct{}

func (approvals) ConsumeApproval(context.Context, string) (domaincredential.Approval, error) {
	return domaincredential.Approval{
		Subject:        "user-1",
		CredentialType: kyc.Type,
		Claims:         map[string]any{kyc.ClaimVerified: true, kyc.ClaimOver18: true, kyc.ClaimCountry: "ID"},
	}, nil
}

// TestVerificationAgainstRealChain issues a credential through the real
// issuance path (which registers it on chain) and verifies it, then checks each
// way the chain can turn it into a rejection.
func TestVerificationAgainstRealChain(t *testing.T) {
	chain := testutil.RequireChain(t)
	client, issuerAuthority := chain.Client(t)
	ctx := context.Background()
	if _, err := client.InitializeRegistry(ctx); err != nil {
		t.Fatal(err)
	}

	const issuerName = "did:example:e2e-issuer"
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := domaincredential.NewSigner(issuerName, priv)
	if err != nil {
		t.Fatal(err)
	}
	issuerID := registry.IssuerID(issuerName)
	if _, err := client.RegisterIssuer(ctx, issuerID, pub, issuerAuthority); err != nil {
		t.Fatal(err)
	}

	issuing, err := credential.NewService(signer, approvals{}, schemas, time.Hour, nil,
		credential.WithBlockchainClient(client))
	if err != nil {
		t.Fatal(err)
	}
	local := domaincredential.NewVerifier(schemas, nil)
	local.Trust(issuerName, pub)
	verifier := verification.NewService(local, policies, verification.WithBlockchainClient(client))

	issue := func() (string, [32]byte) {
		issued, err := issuing.IssueFromApproval(ctx, "a")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		c, err := local.Verify(issued.Token)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Token, registry.CredentialRef(c.ID)
	}
	expect := func(token string, valid bool, reason verification.Reason) {
		t.Helper()
		if res := verifier.Verify(ctx, token); res.Valid != valid || res.Reason != reason {
			t.Fatalf("Valid=%v Reason=%q, want Valid=%v Reason=%q", res.Valid, res.Reason, valid, reason)
		}
	}

	token, ref := issue()
	expect(token, true, "")

	// Revoked on chain.
	if _, err := client.RevokeCredential(ctx, issuerID, ref); err != nil {
		t.Fatal(err)
	}
	expect(token, false, verification.ReasonRevoked)

	// Suspended issuer.
	fresh, _ := issue()
	expect(fresh, true, "")
	if _, err := client.SetIssuerStatus(ctx, issuerID, false); err != nil {
		t.Fatal(err)
	}
	expect(fresh, false, verification.ReasonUntrustedIssuer)
	if _, err := client.SetIssuerStatus(ctx, issuerID, true); err != nil {
		t.Fatal(err)
	}
	expect(fresh, true, "")

	// Credential never registered on chain: signed locally but unknown to the registry.
	unregistered, err := credential.NewService(signer, approvals{}, schemas, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := unregistered.IssueFromApproval(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	expect(issued.Token, false, verification.ReasonNotRegistered)

	// A different key signing for a registered issuer name is rejected even
	// though the registry knows the issuer.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := domaincredential.NewSigner(issuerName, otherPriv)
	rogueIssuing, _ := credential.NewService(otherSigner, approvals{}, schemas, time.Hour, nil)
	rogue, _ := rogueIssuing.IssueFromApproval(ctx, "a")
	expect(rogue.Token, false, verification.ReasonUntrustedIssuer)
}

// TestVerificationFailsClosedWhenChainIsDown points the verifier at a dead
// endpoint: a locally valid credential must be rejected as unavailable, never
// accepted.
func TestVerificationFailsClosedWhenChainIsDown(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := domaincredential.NewSigner("did:example:issuer", priv)
	issuing, _ := credential.NewService(signer, approvals{}, schemas, time.Hour, nil)
	issued, err := issuing.IssueFromApproval(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	local := domaincredential.NewVerifier(schemas, nil)
	local.Trust("did:example:issuer", pub)

	dead, err := blockchain.NewClient(blockchain.Config{
		RPCURL:         "http://127.0.0.1:1",
		ProgramID:      solana.NewWallet().PublicKey().String(),
		Attempts:       2,
		Backoff:        10 * time.Millisecond,
		RequestTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := verification.NewService(local, policies, verification.WithBlockchainClient(dead)).
		Verify(context.Background(), issued.Token)
	if res.Valid || res.Reason != verification.ReasonUnavailable {
		t.Fatalf("Valid=%v Reason=%q, want rejected as unavailable", res.Valid, res.Reason)
	}
}
