package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeVerifier stands in for the credential verifier's API.
func fakeVerifier(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/credentials/verify" {
			t.Errorf("unexpected verifier call %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func present(t *testing.T, verifierURL, credential string) (int, accessResponse) {
	t.Helper()
	a := &app{verifier: verifier{baseURL: verifierURL, client: http.DefaultClient}, log: t.Logf}
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"credential": credential})
	a.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/access", strings.NewReader(string(body))))
	var res accessResponse
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return rec.Code, res
}

func TestValidCredentialIsGrantedAccess(t *testing.T) {
	v := fakeVerifier(t, 200, `{"valid":true,"issuer":"did:example:issuer","credential_type":"KYCStatus","claims":{"kyc_verified":true}}`)
	code, res := present(t, v.URL, "token")
	if code != 200 || res.Access != "granted" || res.Claims["kyc_verified"] != true {
		t.Fatalf("code=%d res=%+v, want granted with the disclosed claims", code, res)
	}
}

func TestRejectedCredentialIsDeniedWithTheVerifiersReason(t *testing.T) {
	for _, reason := range []string{"untrusted_issuer", "revoked", "expired", "invalid_signature"} {
		v := fakeVerifier(t, 200, `{"valid":false,"reason":"`+reason+`"}`)
		code, res := present(t, v.URL, "token")
		if code != 403 || res.Access != "denied" || res.Reason != reason {
			t.Fatalf("%s: code=%d res=%+v, want 403 denied with that reason", reason, code, res)
		}
	}
}

// Whatever goes wrong while asking the verifier, access must not be granted.
func TestAccessIsNeverGrantedWithoutAClearYes(t *testing.T) {
	cases := map[string]*httptest.Server{
		"verifier says unavailable": fakeVerifier(t, 503, `{"valid":false,"reason":"verification_unavailable"}`),
		"verifier server error":     fakeVerifier(t, 500, `{"error":"boom"}`),
		"unreadable reply":          fakeVerifier(t, 200, `<html>`),
		"valid=true on a non-200":   fakeVerifier(t, 502, `{"valid":true}`),
	}
	for name, v := range cases {
		code, res := present(t, v.URL, "token")
		if res.Access == "granted" || code < 400 {
			t.Fatalf("%s: code=%d res=%+v, want denied", name, code, res)
		}
	}

	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL
	down.Close()
	if code, res := present(t, url, "token"); res.Access == "granted" || code != 503 {
		t.Fatalf("verifier down: code=%d res=%+v, want denied with 503", code, res)
	}
}

func TestMissingCredentialIsRejected(t *testing.T) {
	v := fakeVerifier(t, 200, `{"valid":true}`)
	if code, res := present(t, v.URL, ""); code != 400 || res.Access == "granted" {
		t.Fatalf("code=%d res=%+v, want 400 denied", code, res)
	}
}
