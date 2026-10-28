//go:build integration

// Package testutil holds helpers for integration tests that run against the
// local validator started by scripts/integration-test.sh.
package testutil

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/joshia/tokenized-credential-verifier/pkg/connector/blockchain"
)

// Chain describes the local validator and the deployed registry program.
type Chain struct {
	RPCURL    string
	ProgramID string
	// AuthorityKeypair is the registry authority, which is also the program's
	// upgrade authority.
	AuthorityKeypair string
}

// RequireChain reads the validator description from the environment set by
// scripts/integration-test.sh, skipping the test when it is absent.
func RequireChain(t *testing.T) Chain {
	t.Helper()
	get := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			t.Skipf("%s not set; run scripts/integration-test.sh", key)
		}
		return v
	}
	return Chain{
		RPCURL:           get("CREDENTIAL_TEST_RPC_URL"),
		ProgramID:        get("CREDENTIAL_TEST_PROGRAM_ID"),
		AuthorityKeypair: get("CREDENTIAL_TEST_AUTHORITY_KEYPAIR"),
	}
}

// Client returns a connector client with the registry authority and a freshly
// generated, funded issuer authority. It also funds the registry authority.
func (c Chain) Client(t *testing.T) (*blockchain.Client, solana.PublicKey) {
	t.Helper()
	registry, err := blockchain.LoadKeypair(c.AuthorityKeypair)
	if err != nil {
		t.Fatal(err)
	}
	c.Airdrop(t, registry.PublicKey())
	issuerPath, issuerKey := c.FundedKeypair(t)

	client, err := blockchain.NewClient(blockchain.Config{
		RPCURL:                   c.RPCURL,
		ProgramID:                c.ProgramID,
		RegistryAuthorityKeypair: c.AuthorityKeypair,
		IssuerAuthorityKeypair:   issuerPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, issuerKey
}

// FundedKeypair writes a fresh keypair file (solana-keygen JSON) and funds it.
func (c Chain) FundedKeypair(t *testing.T) (path string, pub solana.PublicKey) {
	t.Helper()
	key := solana.NewWallet().PrivateKey
	raw, err := json.Marshal([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "keypair.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c.Airdrop(t, key.PublicKey())
	return path, key.PublicKey()
}

// Airdrop funds an account and waits for the balance to appear.
func (c Chain) Airdrop(t *testing.T, to solana.PublicKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rc := rpc.New(c.RPCURL)
	if _, err := rc.RequestAirdrop(ctx, to, 5*solana.LAMPORTS_PER_SOL, rpc.CommitmentConfirmed); err != nil {
		t.Fatalf("airdrop: %v", err)
	}
	for ctx.Err() == nil {
		if bal, err := rc.GetBalance(ctx, to, rpc.CommitmentConfirmed); err == nil && bal.Value > 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("airdrop never arrived")
}
