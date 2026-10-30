package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeToken builds a compact credential with the given payload. The wallet only
// reads it for display, so the signature is not real.
func fakeToken(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"EdDSA"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("sig"))
}

var kycToken = fakeToken(`{"credential_type":"KYCStatus","exp":1893456000}`)

func TestStoreRoundTrip(t *testing.T) {
	s := store{t.TempDir() + "/wallet"}
	saved, err := s.save(kycToken, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if saved.CredentialType != "KYCStatus" || saved.ExpiresAt.Unix() != 1893456000 {
		t.Fatalf("saved = %+v", saved)
	}
	got, err := s.find(saved.ID[:4])
	if err != nil || got.Credential != kycToken {
		t.Fatalf("find by id prefix = %+v, %v", got, err)
	}
	if latest, err := s.find(""); err != nil || latest.ID != saved.ID {
		t.Fatalf("find newest = %+v, %v", latest, err)
	}
}

func TestStoreRejectsWhatIsNotACredential(t *testing.T) {
	s := store{t.TempDir()}
	for _, bad := range []string{"", "a.b", "a.!!!.c", fakeToken(`{"exp":1}`)} {
		if _, err := s.save(bad, time.Now()); err == nil {
			t.Errorf("save(%q) succeeded, want an error", bad)
		}
	}
	if _, err := s.find(""); err == nil {
		t.Error("find on an empty wallet succeeded, want an error")
	}
}

func TestRequestThenPresent(t *testing.T) {
	var gotClaims map[string]any
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/approvals/simulate":
			var req struct {
				Claims map[string]any `json:"claims"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			gotClaims = req.Claims
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"approval_id":"appr-1","outcome":"approved"}`))
		case "/v1/credentials":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"credential":"` + kycToken + `"}`))
		default:
			t.Errorf("unexpected issuer call %s", r.URL.Path)
		}
	}))
	defer issuer.Close()

	var presented string
	dapp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Credential string `json:"credential"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		presented = req.Credential
		_, _ = w.Write([]byte(`{"access":"granted","claims":{"kyc_verified":true}}`))
	}))
	defer dapp.Close()

	dir := t.TempDir()
	var out bytes.Buffer
	if err := run("request", []string{"-dir", dir, "-api", issuer.URL, "-country", "SG"}, &out); err != nil {
		t.Fatalf("request: %v", err)
	}
	if gotClaims["country"] != "SG" || gotClaims["kyc_verified"] != true {
		t.Fatalf("issuer was asked for claims %v", gotClaims)
	}
	out.Reset()
	if err := run("present", []string{"-dir", dir, "-to", dapp.URL}, &out); err != nil {
		t.Fatalf("present: %v", err)
	}
	if presented != kycToken || !strings.Contains(out.String(), "granted") {
		t.Fatalf("presented %q, output %q", presented, out.String())
	}
}

func TestPresentReportsDenial(t *testing.T) {
	dapp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"access":"denied","reason":"revoked"}`))
	}))
	defer dapp.Close()

	dir := t.TempDir()
	if _, err := (store{dir}).save(kycToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run("present", []string{"-dir", dir, "-to", dapp.URL}, &out); err == nil {
		t.Fatal("present succeeded, want an error when access is denied")
	}
	if !strings.Contains(out.String(), "revoked") {
		t.Fatalf("output %q does not show the reason", out.String())
	}
}

func TestPromptRunsCommandsAndSurvivesErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := (store{dir}).save(kycToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	repl(strings.NewReader("bogus\n\nlist -dir "+dir+"\nexit\nlist -dir "+dir+"\n"), &out)

	got := out.String()
	if !strings.Contains(got, "unknown command") {
		t.Errorf("an unknown command was not reported: %q", got)
	}
	if strings.Count(got, "KYCStatus") != 1 {
		t.Errorf("want list to run once (before exit): %q", got)
	}
}

func TestRevokeSendsTheStoredCredentialAndReportsRefusals(t *testing.T) {
	var got string
	status := http.StatusOK
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/credentials/revoke" {
			t.Errorf("unexpected call %s", r.URL.Path)
		}
		var req struct {
			Credential string `json:"credential"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		got = req.Credential
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"credential is not registered on chain"}`))
	}))
	defer issuer.Close()

	dir := t.TempDir()
	if _, err := (store{dir}).save(kycToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run("revoke", []string{"-dir", dir, "-api", issuer.URL}, &out); err != nil || got != kycToken {
		t.Fatalf("revoke: err=%v sent=%q", err, got)
	}

	status = http.StatusNotFound
	err := run("revoke", []string{"-dir", dir, "-api", issuer.URL}, &out)
	if err == nil || !strings.Contains(err.Error(), "not registered on chain") {
		t.Fatalf("err = %v, want the issuer's refusal shown", err)
	}
}
