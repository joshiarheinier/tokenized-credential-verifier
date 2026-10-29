//go:build integration

package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/issuer"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/testutil"
	"github.com/joshiarheinier/tokenized-credential-verifier/pkg/connector/blockchain"
)

func post(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// TestAppIssuesAndVerifiesAgainstChain boots the real application with registry
// bootstrap enabled and drives it over HTTP: simulate an approval, issue a credential
// (which registers it on chain) and verify it.
func TestAppIssuesAndVerifiesAgainstChain(t *testing.T) {
	chain := testutil.RequireChain(t)

	// The registry authority pays for bootstrap transactions.
	registry, err := blockchain.LoadKeypair(chain.AuthorityKeypair)
	if err != nil {
		t.Fatal(err)
	}
	chain.Airdrop(t, registry.PublicKey())
	issuerKeypair, _ := chain.FundedKeypair(t)

	seed, err := issuer.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"APP_ENV":                           "test",
		"HTTP_ADDR":                         "127.0.0.1:0",
		"ISSUER_ID":                         "did:example:app-integration",
		"ISSUER_SIGNING_KEY_SEED":           seed,
		"SOLANA_RPC_URL":                    chain.RPCURL,
		"SOLANA_PROGRAM_ID":                 chain.ProgramID,
		"SOLANA_REGISTRY_AUTHORITY_KEYPAIR": chain.AuthorityKeypair,
		"SOLANA_ISSUER_AUTHORITY_KEYPAIR":   issuerKeypair,
		"SOLANA_BOOTSTRAP":                  "true",
		"APPROVAL_SIMULATION_ENABLED":       "true",
	}
	cfg, err := config.Load(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	app, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New (bootstrap): %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	serveCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- app.Serve(serveCtx, ln) }()
	defer func() { stop(); <-done }()
	base := "http://" + ln.Addr().String()

	code, sim := post(t, base+"/v1/approvals/simulate", `{"subject":"user-1","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID"}}`)
	if code != http.StatusCreated {
		t.Fatalf("simulate = %d %v", code, sim)
	}
	code, issued := post(t, base+"/v1/credentials", `{"approval_id":"`+sim["approval_id"].(string)+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("issue = %d %v", code, issued)
	}
	code, res := post(t, base+"/v1/credentials/verify", `{"credential":"`+issued["credential"].(string)+`"}`)
	if code != http.StatusOK || res["valid"] != true {
		t.Fatalf("verify = %d %v, want a valid credential confirmed on chain", code, res)
	}

	// A second boot against the same chain must be a clean no-op (idempotent bootstrap).
	if _, err := New(cfg, logger); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
}
