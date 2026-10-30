package http_test

import (
	"context"
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

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/challenge"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/verification"
	domainchallenge "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
	httpgateway "github.com/joshiarheinier/tokenized-credential-verifier/internal/gateways/http"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/challengestore"
)

const walletOrigin = "http://localhost:9091"

type staticVerifier struct{ result verification.Result }

func (v staticVerifier) Verify(context.Context, string) verification.Result { return v.result }

type challengeEnv struct {
	srv    *httptest.Server
	holder ed25519.PrivateKey
}

func newChallengeEnv(t *testing.T) *challengeEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := staticVerifier{verification.Result{
		Valid:          true,
		Issuer:         "did:example:issuer",
		Subject:        domainchallenge.HolderID(pub),
		CredentialType: "KYCStatus",
		ExpiresAt:      time.Now().Add(time.Hour),
		Claims:         map[string]any{"over_18": true, "country": "ID"},
	}}
	svc, err := challenge.NewService(challengestore.NewMemory(100), verifier, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(httpgateway.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		httpgateway.API{Challenges: svc, AllowedOrigins: []string{walletOrigin}}))
	t.Cleanup(srv.Close)
	return &challengeEnv{srv: srv, holder: priv}
}

func (e *challengeEnv) do(t *testing.T, method, path, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
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

func TestChallengeResponseHappyPathOverHTTP(t *testing.T) {
	e := newChallengeEnv(t)

	// 1. The relying application creates a challenge.
	code, created := e.do(t, "POST", "/v1/challenges",
		`{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"],"callback_url":"http://localhost:9090/callback"}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("create = %d %v", code, created)
	}
	id, secret := created["challenge_id"].(string), created["result_secret"].(string)

	// 2. The wallet reads it, with no secret in the response.
	code, view := e.do(t, "GET", "/v1/challenges/"+id, "", nil)
	if code != http.StatusOK || view["status"] != "pending" || view["audience"] != "http://localhost:9090" {
		t.Fatalf("get = %d %v", code, view)
	}
	if _, leaked := view["result_secret"]; leaked {
		t.Fatal("the wallet's view of a challenge contains the result secret")
	}

	// 3. The holder signs what the wallet shows and submits.
	expires, _ := time.Parse(time.RFC3339, view["expires_at"].(string))
	challenge := domainchallenge.Challenge{
		ID: id, Audience: view["audience"].(string), CredentialType: view["credential_type"].(string),
		Claims: []string{"over_18"}, ExpiresAt: expires,
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(e.holder, []byte(domainchallenge.Message(challenge, "the-credential"))))
	code, res := e.do(t, "POST", "/v1/challenges/"+id+"/response",
		`{"credential":"the-credential","holder_signature":"`+sig+`"}`, nil)
	if code != http.StatusOK || res["status"] != "verified" {
		t.Fatalf("respond = %d %v", code, res)
	}
	if _, leaked := res["claims"]; leaked {
		t.Fatal("the wallet's answer to submitting a response contains claims")
	}

	// 4. Only the creator reads the verdict, and only the requested claim is in it.
	bearer := map[string]string{"Authorization": "Bearer " + secret}
	code, result := e.do(t, "GET", "/v1/challenges/"+id+"/result", "", bearer)
	claims, _ := result["claims"].(map[string]any)
	if code != http.StatusOK || result["status"] != "verified" || len(claims) != 1 || claims["over_18"] != true {
		t.Fatalf("result = %d %v, want verified with only over_18", code, result)
	}

	// 5. The challenge cannot be used again.
	if code, _ := e.do(t, "POST", "/v1/challenges/"+id+"/response",
		`{"credential":"the-credential","holder_signature":"`+sig+`"}`, nil); code != http.StatusConflict {
		t.Fatalf("second response = %d, want 409", code)
	}
}

func TestResultNeedsTheSecret(t *testing.T) {
	e := newChallengeEnv(t)
	_, created := e.do(t, "POST", "/v1/challenges", `{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"]}`, nil)
	path := "/v1/challenges/" + created["challenge_id"].(string) + "/result"

	if code, _ := e.do(t, "GET", path, "", nil); code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", code)
	}
	if code, _ := e.do(t, "GET", path, "", map[string]string{"Authorization": "Bearer wrong"}); code != http.StatusNotFound {
		t.Errorf("wrong secret = %d, want 404", code)
	}
	if code, _ := e.do(t, "GET", "/v1/challenges/unknown/result", "", map[string]string{"Authorization": "Bearer wrong"}); code != http.StatusNotFound {
		t.Errorf("unknown challenge = %d, want the same 404", code)
	}
	if code, res := e.do(t, "GET", path, "", map[string]string{"Authorization": "Bearer " + created["result_secret"].(string)}); code != http.StatusOK || res["status"] != "pending" {
		t.Errorf("right secret = %d %v, want pending", code, res)
	}
}

func TestChallengeRequestsAreValidated(t *testing.T) {
	e := newChallengeEnv(t)
	for name, body := range map[string]string{
		"audience over plain http": `{"audience":"http://app.example","credential_type":"KYCStatus","claims":["over_18"]}`,
		"no claims":                `{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":[]}`,
		"callback elsewhere":       `{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"],"callback_url":"https://evil.example/cb"}`,
		"unknown field":            `{"audience":"http://localhost:9090","credential_type":"KYCStatus","claims":["over_18"],"extra":1}`,
	} {
		if code, _ := e.do(t, "POST", "/v1/challenges", body, nil); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, code)
		}
	}
	if code, _ := e.do(t, "GET", "/v1/challenges/unknown", "", nil); code != http.StatusNotFound {
		t.Errorf("unknown challenge = %d, want 404", code)
	}
	if code, _ := e.do(t, "POST", "/v1/challenges/x/response", `{"credential":"t","holder_signature":"!!!"}`, nil); code != http.StatusBadRequest {
		t.Errorf("bad signature encoding = %d, want 400", code)
	}
}

func TestCORSAllowsOnlyTheConfiguredOrigins(t *testing.T) {
	e := newChallengeEnv(t)
	preflight := func(origin string) *http.Response {
		req, _ := http.NewRequest(http.MethodOptions, e.srv.URL+"/v1/challenges/x/response", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	ok := preflight(walletOrigin)
	if ok.StatusCode != http.StatusNoContent || ok.Header.Get("Access-Control-Allow-Origin") != walletOrigin {
		t.Fatalf("allowed origin: %d, Allow-Origin=%q", ok.StatusCode, ok.Header.Get("Access-Control-Allow-Origin"))
	}
	if got := ok.Header.Get("Access-Control-Allow-Headers"); got != "Content-Type" {
		t.Errorf("Allow-Headers = %q: Authorization must not be allowed cross-origin", got)
	}
	if bad := preflight("https://evil.example"); bad.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("a disallowed origin was granted access: %q", bad.Header.Get("Access-Control-Allow-Origin"))
	}

	// A real response to an allowed origin carries the header too.
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/challenges/unknown", nil)
	req.Header.Set("Origin", walletOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") != walletOrigin {
		t.Errorf("a simple request from the wallet origin got no Allow-Origin header")
	}
}
