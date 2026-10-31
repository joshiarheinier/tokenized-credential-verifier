package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
	domainchallenge "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/issuer"
)

// Attacks on the challenge-response protocol, against the real server and the
// real credential verification. The chain is not involved (no registry is
// configured), so these run without a validator; the chain-backed rejections
// are in integration_test.go.

const attackAudience = "http://localhost:9090"

// testServer runs the real server, without a registry, and returns its URL.
func testServer(t *testing.T, extra map[string]string) string {
	t.Helper()
	seed, err := issuer.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"APP_ENV": "test", "ISSUER_SIGNING_KEY_SEED": seed}
	for k, v := range extra {
		vars[k] = v
	}
	cfg, err := config.Load(func(k string) string { return vars[k] })
	if err != nil {
		t.Fatal(err)
	}
	srv, err := newServer(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)
	return ts.URL
}

// wallet is a holder's key and what a wallet does with it.
type wallet struct {
	pub ed25519.PublicKey
	key ed25519.PrivateKey
}

func newWallet(t *testing.T) wallet {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return wallet{pub, key}
}

func (w wallet) id() string { return domainchallenge.HolderID(w.pub) }

// issueTo obtains a credential for subject through the API: simulate an
// approval, then issue it.
func issueTo(t *testing.T, base, subject string) string {
	t.Helper()
	code, sim := doJSON(t, "POST", base+"/v1/approvals/simulate",
		`{"subject":"`+subject+`","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID"}}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("simulate = %d %v", code, sim)
	}
	code, issued := doJSON(t, "POST", base+"/v1/credentials", `{"approval_id":"`+sim["approval_id"].(string)+`"}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("issue = %d %v", code, issued)
	}
	return issued["credential"].(string)
}

// openChallenge is a relying application asking for over_18. It returns the
// challenge id and the secret for reading the result.
func openChallenge(t *testing.T, base string) (id, secret string) {
	t.Helper()
	code, created := doJSON(t, "POST", base+"/v1/challenges",
		`{"audience":"`+attackAudience+`","credential_type":"KYCStatus","claims":["over_18"]}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("create challenge = %d %v", code, created)
	}
	return created["challenge_id"].(string), created["result_secret"].(string)
}

// sign is the wallet reading challenge id from the verifier and signing the
// answer for token, as the user would approve it.
func (w wallet) sign(t *testing.T, base, id, token string) string {
	t.Helper()
	code, view := doJSON(t, "GET", base+"/v1/challenges/"+id, "", nil)
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
	return base64.StdEncoding.EncodeToString(ed25519.Sign(w.key, []byte(message)))
}

func respond(t *testing.T, base, id, token, signature string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, "POST", base+"/v1/challenges/"+id+"/response", `{"credential":"`+token+`","holder_signature":"`+signature+`"}`, nil)
}

func readResult(t *testing.T, base, id, secret string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, "GET", base+"/v1/challenges/"+id+"/result", "", map[string]string{"Authorization": "Bearer " + secret})
}

func requireRejection(t *testing.T, base, id, secret string, answered map[string]any, wantReason string) {
	t.Helper()
	if answered["status"] != "rejected" || answered["reason"] != wantReason {
		t.Fatalf("answer = %v, want rejected with %s", answered, wantReason)
	}
	_, result := readResult(t, base, id, secret)
	if result["status"] != "rejected" || result["claims"] != nil || result["issuer"] != nil {
		t.Fatalf("result = %v: a rejection must show the application no claims", result)
	}
}

// A holder edits their own credential, say to change the country, and signs the
// challenge for the edited copy. The issuer's signature no longer fits.
func TestAnEditedCredentialIsRejected(t *testing.T) {
	base := testServer(t, nil)
	holder := newWallet(t)
	token := issueTo(t, base, holder.id())

	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(payload), `"country":"ID"`, `"country":"US"`, 1)
	if edited == string(payload) {
		t.Fatalf("test setup: no country in the payload %s", payload)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(edited))
	forged := strings.Join(parts, ".")

	id, secret := openChallenge(t, base)
	code, answered := respond(t, base, id, forged, holder.sign(t, base, id, forged))
	if code != http.StatusOK {
		t.Fatalf("respond = %d %v", code, answered)
	}
	requireRejection(t, base, id, secret, answered, "invalid_signature")
}

// A credential issued to a name rather than to a key cannot answer: nobody can
// prove they are that name.
func TestACredentialNotIssuedToAHolderKeyIsRejected(t *testing.T) {
	base := testServer(t, nil)
	token := issueTo(t, base, "user-1")
	holder := newWallet(t)

	id, secret := openChallenge(t, base)
	_, answered := respond(t, base, id, token, holder.sign(t, base, id, token))
	requireRejection(t, base, id, secret, answered, "holder_binding_failed")
}

// Someone who captures a whole response, credential and signature, cannot use
// it for the challenge they were given.
func TestACapturedResponseIsUselessOnAnotherChallenge(t *testing.T) {
	base := testServer(t, nil)
	holder := newWallet(t)
	token := issueTo(t, base, holder.id())

	first, _ := openChallenge(t, base)
	captured := holder.sign(t, base, first, token)
	if _, answered := respond(t, base, first, token, captured); answered["status"] != "verified" {
		t.Fatalf("the real answer: %v", answered)
	}

	second, secret := openChallenge(t, base)
	_, answered := respond(t, base, second, token, captured)
	requireRejection(t, base, second, secret, answered, "holder_binding_failed")
}

// The same valid response sent many times at once: exactly one is counted.
func TestConcurrentSubmissionsOfOneResponseAreCountedOnce(t *testing.T) {
	base := testServer(t, nil)
	holder := newWallet(t)
	token := issueTo(t, base, holder.id())
	id, secret := openChallenge(t, base)
	signature := holder.sign(t, base, id, token)

	const attempts = 10
	codes := make(chan int, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := respond(t, base, id, token, signature)
			codes <- code
		}()
	}
	wg.Wait()
	close(codes)

	answered, refused := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			answered++
		case http.StatusConflict:
			refused++
		default:
			t.Errorf("unexpected status %d", code)
		}
	}
	if answered != 1 || refused != attempts-1 {
		t.Fatalf("%d answered, %d refused as used, want 1 and %d", answered, refused, attempts-1)
	}
	if _, result := readResult(t, base, id, secret); result["status"] != "verified" {
		t.Fatalf("result = %v, want the one answer to stand", result)
	}
}

func TestAnExpiredChallengeCannotBeAnswered(t *testing.T) {
	base := testServer(t, map[string]string{"CHALLENGE_TTL": "1s"})
	holder := newWallet(t)
	token := issueTo(t, base, holder.id())
	id, secret := openChallenge(t, base)
	signature := holder.sign(t, base, id, token)

	time.Sleep(1200 * time.Millisecond)

	if code, _ := doJSON(t, "GET", base+"/v1/challenges/"+id, "", nil); code != http.StatusGone {
		t.Errorf("wallet fetch = %d, want 410", code)
	}
	if code, _ := respond(t, base, id, token, signature); code != http.StatusGone {
		t.Errorf("response = %d, want 410", code)
	}
	if code, result := readResult(t, base, id, secret); code != http.StatusOK || result["status"] != "expired" {
		t.Errorf("result = %d %v, want expired", code, result)
	}
}

func TestAnOversizedResponseIsRefused(t *testing.T) {
	base := testServer(t, nil)
	id, _ := openChallenge(t, base)
	code, _ := respond(t, base, id, strings.Repeat("a", 2<<20), "AAAA")
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 2 MB credential = %d, want 413", code)
	}
}
