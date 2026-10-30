package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
	domainchallenge "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/issuer"
)

func doJSON(t *testing.T, method, url, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

// TestChallengeResponseFlowEndToEnd is the happy path of the challenge-response protocol
// through the real server and the real credential verification: a credential is
// issued to a holder's key, a relying application asks for one claim, the holder
// signs and presents, and only that claim reaches the application. The chain is
// not involved (no registry is configured), so this runs without a validator.
func TestChallengeResponseFlowEndToEnd(t *testing.T) {
	seed, err := issuer.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"APP_ENV": "test", "ISSUER_SIGNING_KEY_SEED": seed}
	cfg, err := config.Load(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// The issuer issues a KYC credential to the holder's key.
	code, sim := doJSON(t, "POST", ts.URL+"/v1/approvals/simulate",
		`{"subject":"`+domainchallenge.HolderID(holderPub)+`","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID"}}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("simulate = %d %v", code, sim)
	}
	code, issued := doJSON(t, "POST", ts.URL+"/v1/credentials", `{"approval_id":"`+sim["approval_id"].(string)+`"}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("issue = %d %v", code, issued)
	}
	token := issued["credential"].(string)

	// The relying application asks for one claim.
	code, created := doJSON(t, "POST", ts.URL+"/v1/challenges",
		`{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"]}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("create challenge = %d %v", code, created)
	}
	id, secret := created["challenge_id"].(string), created["result_secret"].(string)

	// The wallet shows the request, the holder signs the text built from it.
	code, view := doJSON(t, "GET", ts.URL+"/v1/challenges/"+id, "", nil)
	if code != http.StatusOK {
		t.Fatalf("get challenge = %d %v", code, view)
	}
	expires, err := time.Parse(time.RFC3339, view["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	message := domainchallenge.Message(domainchallenge.Challenge{
		ID: id, Audience: view["audience"].(string), CredentialType: view["credential_type"].(string),
		Claims: []string{"over_18"}, ExpiresAt: expires,
	}, token)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(holderKey, []byte(message)))

	code, answered := doJSON(t, "POST", ts.URL+"/v1/challenges/"+id+"/response",
		`{"credential":"`+token+`","holder_signature":"`+signature+`"}`, nil)
	if code != http.StatusOK || answered["status"] != "verified" {
		t.Fatalf("respond = %d %v, want verified", code, answered)
	}

	// The application reads the verdict: only the requested claim.
	code, result := doJSON(t, "GET", ts.URL+"/v1/challenges/"+id+"/result", "", map[string]string{"Authorization": "Bearer " + secret})
	claims, _ := result["claims"].(map[string]any)
	if code != http.StatusOK || result["status"] != "verified" || len(claims) != 1 || claims["over_18"] != true {
		t.Fatalf("result = %d %v, want verified with only over_18", code, result)
	}

	// A signature by anyone else does not work, even for a valid credential.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	_, second := doJSON(t, "POST", ts.URL+"/v1/challenges", `{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"]}`, nil)
	id2 := second["challenge_id"].(string)
	_, view2 := doJSON(t, "GET", ts.URL+"/v1/challenges/"+id2, "", nil)
	expires2, _ := time.Parse(time.RFC3339, view2["expires_at"].(string))
	forged := base64.StdEncoding.EncodeToString(ed25519.Sign(stranger, []byte(domainchallenge.Message(domainchallenge.Challenge{
		ID: id2, Audience: "http://localhost:9090", CredentialType: "KYCStatus", Claims: []string{"over_18"}, ExpiresAt: expires2,
	}, token))))
	_, rejected := doJSON(t, "POST", ts.URL+"/v1/challenges/"+id2+"/response",
		`{"credential":"`+token+`","holder_signature":"`+forged+`"}`, nil)
	if rejected["status"] != "rejected" || rejected["reason"] != "holder_binding_failed" {
		t.Fatalf("a signature by another key: %v, want rejected with holder_binding_failed", rejected)
	}
}
