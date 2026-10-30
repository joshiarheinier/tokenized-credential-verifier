//go:build integration

// End-to-end scenarios for Phase 4: the real server, driven over HTTP, against
// a real validator running the registry program. Each test is one acceptance
// criterion: a valid credential from a trusted issuer is accepted; an untrusted
// issuer's, a revoked and an expired credential are rejected; and an RPC outage
// never lets an unverified credential through.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential/kyc"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/issuer"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/testutil"
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

// stack is the real server booted against the validator, with registry
// bootstrap enabled so it has its own freshly registered issuer.
type stack struct {
	base     string
	issuerID string
	seed     string
	chain    testutil.Chain
	cfg      config.Config
	logger   *slog.Logger
}

// newStack boots the server with extra settings layered over the defaults. Each
// stack gets its own issuer id because the validator is shared between tests and
// the registry refuses to re-register an issuer under a different key.
func newStack(t *testing.T, extra map[string]string) *stack {
	t.Helper()
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
	s := &stack{
		issuerID: fmt.Sprintf("did:example:scenario-%d", time.Now().UnixNano()),
		seed:     seed,
		chain:    chain,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	vars := map[string]string{
		"APP_ENV":                           "test",
		"HTTP_ADDR":                         "127.0.0.1:0",
		"ISSUER_ID":                         s.issuerID,
		"ISSUER_SIGNING_KEY_SEED":           seed,
		"SOLANA_RPC_URL":                    chain.RPCURL,
		"SOLANA_PROGRAM_ID":                 chain.ProgramID,
		"SOLANA_REGISTRY_AUTHORITY_KEYPAIR": chain.AuthorityKeypair,
		"SOLANA_ISSUER_AUTHORITY_KEYPAIR":   issuerKeypair,
		"SOLANA_BOOTSTRAP":                  "true",
		"APPROVAL_SIMULATION_ENABLED":       "true",
	}
	for k, v := range extra {
		vars[k] = v
	}
	s.base = s.serve(t, vars)
	return s
}

// serve runs the real server configured by vars and returns its base URL. It is
// stopped when the test ends.
func (s *stack) serve(t *testing.T, vars map[string]string) string {
	t.Helper()
	cfg, err := config.Load(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = cfg
	srv, err := newServer(cfg, s.logger)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	serveCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- serve(serveCtx, srv, ln, cfg, s.logger) }()
	t.Cleanup(func() { stop(); <-done; cancel() })
	return "http://" + ln.Addr().String()
}

// issue obtains a credential through the HTTP API: simulate an approval, then
// issue it, which registers the credential on chain.
func (s *stack) issue(t *testing.T) string {
	t.Helper()
	code, sim := post(t, s.base+"/v1/approvals/simulate", `{"subject":"user-1","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID"}}`)
	if code != http.StatusCreated {
		t.Fatalf("simulate = %d %v", code, sim)
	}
	code, issued := post(t, s.base+"/v1/credentials", `{"approval_id":"`+sim["approval_id"].(string)+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("issue = %d %v", code, issued)
	}
	return issued["credential"].(string)
}

// verify asks the verifier at base and returns its HTTP status and, for a
// rejection, the reason.
func verify(t *testing.T, base, token string) (code int, valid bool, reason string) {
	t.Helper()
	code, res := post(t, base+"/v1/credentials/verify", `{"credential":"`+token+`"}`)
	valid, _ = res["valid"].(bool)
	reason, _ = res["reason"].(string)
	return code, valid, reason
}

func requireValid(t *testing.T, base, token string) {
	t.Helper()
	if code, valid, reason := verify(t, base, token); code != http.StatusOK || !valid {
		t.Fatalf("verify = %d valid=%v reason=%q, want a valid credential confirmed on chain", code, valid, reason)
	}
}

func requireRejected(t *testing.T, base, token, wantReason string, wantCode int) {
	t.Helper()
	code, valid, reason := verify(t, base, token)
	if valid || reason != wantReason || code != wantCode {
		t.Fatalf("verify = %d valid=%v reason=%q, want rejected with %q (HTTP %d)", code, valid, reason, wantReason, wantCode)
	}
}

func TestValidCredentialFromTrustedIssuerIsAccepted(t *testing.T) {
	s := newStack(t, nil)
	requireValid(t, s.base, s.issue(t))

	// A second boot against the same chain must be a clean no-op (idempotent bootstrap).
	if _, err := newServer(s.cfg, s.logger); err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}
}

func TestRevokedCredentialIsRejected(t *testing.T) {
	s := newStack(t, nil)
	token := s.issue(t)
	other := s.issue(t)
	requireValid(t, s.base, token)

	if code, res := post(t, s.base+"/v1/credentials/revoke", `{"credential":"`+token+`"}`); code != http.StatusOK {
		t.Fatalf("revoke = %d %v", code, res)
	}
	requireRejected(t, s.base, token, "revoked", http.StatusOK)
	requireValid(t, s.base, other) // only that credential was revoked

	if code, _ := post(t, s.base+"/v1/credentials/revoke", `{"credential":"`+token+`"}`); code != http.StatusOK {
		t.Fatalf("revoking again = %d, want a harmless no-op", code)
	}
}

func TestUntrustedIssuersCredentialIsRejected(t *testing.T) {
	s := newStack(t, nil)

	t.Run("issuer suspended in the registry", func(t *testing.T) {
		token := s.issue(t)
		requireValid(t, s.base, token)

		if code, res := post(t, s.base+"/v1/issuer/suspend", ""); code != http.StatusOK {
			t.Fatalf("suspend = %d %v", code, res)
		}
		requireRejected(t, s.base, token, "untrusted_issuer", http.StatusOK)

		if code, res := post(t, s.base+"/v1/issuer/reactivate", ""); code != http.StatusOK {
			t.Fatalf("reactivate = %d %v", code, res)
		}
		requireValid(t, s.base, token)
	})

	t.Run("issuer never registered", func(t *testing.T) {
		// A well-formed credential, correctly signed, by an issuer the registry
		// has never heard of.
		seed, err := issuer.GenerateSeed()
		if err != nil {
			t.Fatal(err)
		}
		rogue, err := issuer.New("did:example:rogue", seed)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		token, err := rogue.Signer.Sign(credential.Claims{
			Subject:        "user-1",
			ID:             "rogue-credential",
			IssuedAt:       now.Unix(),
			ExpiresAt:      now.Add(time.Hour).Unix(),
			CredentialType: kyc.Type,
			Attributes:     map[string]any{kyc.ClaimVerified: true, kyc.ClaimOver18: true, kyc.ClaimCountry: "ID"},
		})
		if err != nil {
			t.Fatal(err)
		}
		requireRejected(t, s.base, token, "untrusted_issuer", http.StatusOK)
	})
}

func TestExpiredCredentialIsRejected(t *testing.T) {
	s := newStack(t, map[string]string{"CREDENTIAL_TTL": "2s"})
	token := s.issue(t)
	requireValid(t, s.base, token)

	time.Sleep(3 * time.Second)
	requireRejected(t, s.base, token, "expired", http.StatusOK)
}

// When the chain cannot be read the verifier must not accept anything: a
// credential that is valid and registered is still refused, with a 503 that
// says "could not verify" rather than "invalid".
func TestRPCOutageNeverAcceptsACredential(t *testing.T) {
	s := newStack(t, nil)
	token := s.issue(t)
	requireValid(t, s.base, token)

	// The same issuer's verifier, but its RPC node is unreachable.
	deadRPC := s.serve(t, map[string]string{
		"APP_ENV":                     "test",
		"HTTP_ADDR":                   "127.0.0.1:0",
		"ISSUER_ID":                   s.issuerID,
		"ISSUER_SIGNING_KEY_SEED":     s.seed,
		"SOLANA_RPC_URL":              "http://127.0.0.1:1",
		"SOLANA_PROGRAM_ID":           s.chain.ProgramID,
		"SOLANA_REQUEST_TIMEOUT":      "2s",
		"APPROVAL_SIMULATION_ENABLED": "false",
	})
	requireRejected(t, deadRPC, token, "verification_unavailable", http.StatusServiceUnavailable)
}
