//go:build integration

package verification_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/joshia/tokenized-identity-kyc/internal/credential"
	"github.com/joshia/tokenized-identity-kyc/internal/testutil"
	"github.com/joshia/tokenized-identity-kyc/internal/verification"
	"github.com/joshia/tokenized-identity-kyc/pkg/connector/blockchain"
)

type approvals struct{}

func (approvals) ConsumeApproval(context.Context, string) (credential.Approval, error) {
	return credential.Approval{Subject: "user-1", Claims: credential.KYCClaims{KYCVerified: true, Over18: true, Country: "ID"}}, nil
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
	signer, err := credential.NewSigner(issuerName, priv)
	if err != nil {
		t.Fatal(err)
	}
	issuerID := blockchain.IssuerID(issuerName)
	if _, err := client.RegisterIssuer(ctx, issuerID, pub, issuerAuthority); err != nil {
		t.Fatal(err)
	}

	issuing, err := credential.NewService(signer, approvals{}, time.Hour, nil,
		credential.WithBlockchainClient(client))
	if err != nil {
		t.Fatal(err)
	}
	local := credential.NewVerifier(nil)
	local.Trust(issuerName, pub)
	verifier := verification.NewService(local, verification.DefaultPolicy, verification.WithBlockchainClient(client))

	issue := func() (string, [32]byte) {
		issued, err := issuing.IssueFromApproval(ctx, "a")
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		c, err := local.Verify(issued.Token)
		if err != nil {
			t.Fatal(err)
		}
		return issued.Token, blockchain.CredentialRef(c.ID)
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
	unregistered, err := credential.NewService(signer, approvals{}, time.Hour, nil)
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
	otherSigner, _ := credential.NewSigner(issuerName, otherPriv)
	rogueIssuing, _ := credential.NewService(otherSigner, approvals{}, time.Hour, nil)
	rogue, _ := rogueIssuing.IssueFromApproval(ctx, "a")
	expect(rogue.Token, false, verification.ReasonUntrustedIssuer)
}

// TestVerificationFailsClosedWhenChainIsDown points the verifier at a dead
// endpoint: a locally valid credential must be rejected as unavailable, never
// accepted.
func TestVerificationFailsClosedWhenChainIsDown(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := credential.NewSigner("did:example:issuer", priv)
	issuing, _ := credential.NewService(signer, approvals{}, time.Hour, nil)
	issued, err := issuing.IssueFromApproval(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	local := credential.NewVerifier(nil)
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
	res := verification.NewService(local, verification.DefaultPolicy, verification.WithBlockchainClient(dead)).
		Verify(context.Background(), issued.Token)
	if res.Valid || res.Reason != verification.ReasonUnavailable {
		t.Fatalf("Valid=%v Reason=%q, want rejected as unavailable", res.Valid, res.Reason)
	}
}
