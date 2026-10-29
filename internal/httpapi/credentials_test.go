package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/approval"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/credential/kyc"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/httpapi"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/issuer"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/verification"
)

var startTime = time.Unix(1_793_000_000, 0)

// A non-KYC credential type, to show the HTTP layer is not tied to KYC.
const membershipType = "Membership"

var membershipSchema = credential.Schema{
	Type: membershipType,
	Fields: []credential.Field{
		{Name: "tier", Kind: credential.String, Required: true},
		{Name: "member_since", Kind: credential.Number},
	},
}

type testEnv struct {
	srv *httptest.Server
	now *time.Time
	iss *issuer.Issuer
}

func newEnv(t *testing.T, withIssuance bool) *testEnv {
	t.Helper()
	seed, _ := issuer.GenerateSeed()
	iss, err := issuer.New("did:example:issuer", seed)
	if err != nil {
		t.Fatal(err)
	}
	now := startTime
	clock := func() time.Time { return now }

	schemas, err := credential.NewSchemas(kyc.Schema, membershipSchema)
	if err != nil {
		t.Fatal(err)
	}
	policies := []verification.Policy{
		{CredentialType: kyc.Type, Require: []verification.Requirement{{Claim: kyc.ClaimVerified, Equals: true}}},
		{CredentialType: membershipType, Require: []verification.Requirement{{Claim: "tier", Equals: "gold"}}, Disclose: []string{"tier"}},
	}
	v := credential.NewVerifier(schemas, clock)
	v.Trust(iss.ID, iss.Signer.PublicKey())
	api := httpapi.API{CredentialVerification: verification.NewService(v, policies)}
	if withIssuance {
		approvals := approval.NewService(schemas)
		svc, err := credential.NewService(iss.Signer, approvals, schemas, time.Hour, clock)
		if err != nil {
			t.Fatal(err)
		}
		api.ApprovalSimulation, api.CredentialIssuance = approvals, svc
	}
	srv := httptest.NewServer(httpapi.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), api))
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, now: &now, iss: iss}
}

func (e *testEnv) post(t *testing.T, path, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(e.srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (e *testEnv) issueCredential(t *testing.T, simBody string) string {
	t.Helper()
	code, sim := e.post(t, "/v1/approvals/simulate", simBody)
	if code != http.StatusCreated {
		t.Fatalf("simulate = %d %v", code, sim)
	}
	code, iss := e.post(t, "/v1/credentials", `{"approval_id":"`+sim["approval_id"].(string)+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("issue = %d %v", code, iss)
	}
	return iss["credential"].(string)
}

const approved = `{"subject":"user-1","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID"}}`

func TestIssueAndVerifyFlow(t *testing.T) {
	e := newEnv(t, true)
	token := e.issueCredential(t, approved)

	code, res := e.post(t, "/v1/credentials/verify", `{"credential":"`+token+`"}`)
	if code != http.StatusOK || res["valid"] != true {
		t.Fatalf("verify = %d %v", code, res)
	}
	claims := res["claims"].(map[string]any)
	if claims["kyc_verified"] != true || claims["country"] != "ID" || claims["over_18"] != true {
		t.Errorf("claims = %v", claims)
	}
	for _, leaked := range []string{"sub", "subject", "jti", "credential"} {
		if _, ok := res[leaked]; ok {
			t.Errorf("verify response exposes %q", leaked)
		}
	}
}

func TestVerifyRejections(t *testing.T) {
	e := newEnv(t, true)
	token := e.issueCredential(t, approved)
	parts := strings.Split(token, ".")

	// Modified payload: flip the country in the (still validly encoded) payload.
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	forgedPayload := strings.Replace(string(payload), `"ID"`, `"KP"`, 1)
	if forgedPayload == string(payload) {
		t.Fatal("test did not modify payload")
	}
	tampered := parts[0] + "." + enc.EncodeToString([]byte(forgedPayload)) + "." + parts[2]

	otherSeed, _ := issuer.GenerateSeed()
	other, _ := issuer.New(e.iss.ID, otherSeed)
	foreign, _ := other.Signer.Sign(credential.Claims{
		Subject: "u", ID: "j", IssuedAt: startTime.Unix(), ExpiresAt: startTime.Add(time.Hour).Unix(),
		CredentialType: kyc.Type,
		Attributes:     map[string]any{"kyc_verified": true, "over_18": true, "country": "ID"},
	})

	tests := []struct {
		name, token, reason string
		advance             time.Duration
	}{
		{"modified payload", tampered, "invalid_signature", 0},
		{"unknown signing key", foreign, "untrusted_issuer", 0},
		{"expired", token, "expired", 2 * time.Hour},
		{"garbage", "not-a-credential", "malformed", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*e.now = startTime.Add(tt.advance)
			code, res := e.post(t, "/v1/credentials/verify", `{"credential":"`+tt.token+`"}`)
			if code != http.StatusOK || res["valid"] != false || res["reason"] != tt.reason {
				t.Fatalf("verify = %d %v, want invalid/%s", code, res, tt.reason)
			}
			if _, ok := res["claims"]; ok {
				t.Error("claims returned for invalid credential")
			}
		})
	}
}

func TestPolicyRejectsUnverifiedClaims(t *testing.T) {
	e := newEnv(t, false)
	// Correctly signed and well-formed, but attests kyc_verified=false.
	token, _ := e.iss.Signer.Sign(credential.Claims{
		Subject: "u", ID: "j", IssuedAt: startTime.Unix(), ExpiresAt: startTime.Add(time.Hour).Unix(),
		CredentialType: kyc.Type,
		Attributes:     map[string]any{"kyc_verified": false, "over_18": false, "country": "ID"},
	})
	_, res := e.post(t, "/v1/credentials/verify", `{"credential":"`+token+`"}`)
	if res["valid"] != false || res["reason"] != "policy_not_satisfied" {
		t.Fatalf("verify = %v", res)
	}
}

func TestRejectedApprovalDoesNotIssue(t *testing.T) {
	e := newEnv(t, true)
	_, sim := e.post(t, "/v1/approvals/simulate", `{"subject":"user-2","outcome":"rejected"}`)
	code, _ := e.post(t, "/v1/credentials", `{"approval_id":"`+sim["approval_id"].(string)+`"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("issue after rejection = %d, want 422", code)
	}
}

func TestApprovalIsSingleUse(t *testing.T) {
	e := newEnv(t, true)
	_, sim := e.post(t, "/v1/approvals/simulate", approved)
	body := `{"approval_id":"` + sim["approval_id"].(string) + `"}`
	if code, _ := e.post(t, "/v1/credentials", body); code != http.StatusCreated {
		t.Fatalf("first issue = %d", code)
	}
	if code, _ := e.post(t, "/v1/credentials", body); code != http.StatusConflict {
		t.Fatalf("second issue = %d, want 409", code)
	}
}

func TestIssueUnknownResult(t *testing.T) {
	e := newEnv(t, true)
	if code, _ := e.post(t, "/v1/credentials", `{"approval_id":"nope"}`); code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", code)
	}
}

func TestBadRequests(t *testing.T) {
	e := newEnv(t, true)
	tests := []struct{ name, path, body string }{
		{"simulate bad json", "/v1/approvals/simulate", `{`},
		{"simulate unknown field", "/v1/approvals/simulate", `{"subject":"a","credential_type":"KYCStatus","outcome":"approved","admin":1}`},
		{"simulate trailing data", "/v1/approvals/simulate", approved + `{}`},
		{"simulate missing subject", "/v1/approvals/simulate", `{"credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID"}}`},
		{"simulate bad outcome", "/v1/approvals/simulate", `{"subject":"a","outcome":"maybe"}`},
		{"simulate unknown credential type", "/v1/approvals/simulate", `{"subject":"a","credential_type":"Nope","outcome":"approved","claims":{}}`},
		{"simulate bad country", "/v1/approvals/simulate", `{"subject":"a","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"Indonesia"}}`},
		{"simulate missing claim", "/v1/approvals/simulate", `{"subject":"a","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true}}`},
		{"simulate unexpected claim", "/v1/approvals/simulate", `{"subject":"a","credential_type":"KYCStatus","outcome":"approved","claims":{"kyc_verified":true,"over_18":true,"country":"ID","name":"Ada"}}`},
		{"issue missing id", "/v1/credentials", `{}`},
		{"verify missing credential", "/v1/credentials/verify", `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code, _ := e.post(t, tt.path, tt.body); code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400", code)
			}
		})
	}
	big := `{"credential":"` + strings.Repeat("a", 32*1024) + `"}`
	if code, _ := e.post(t, "/v1/credentials/verify", big); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body code = %d, want 413", code)
	}
}

func TestIssuanceRoutesAbsentWithoutSimulation(t *testing.T) {
	e := newEnv(t, false)
	for _, path := range []string{"/v1/approvals/simulate", "/v1/credentials"} {
		if code, _ := e.post(t, path, approved); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s code = %d, want 404/405", path, code)
		}
	}
	if code, _ := e.post(t, "/v1/credentials/verify", `{"credential":"x"}`); code != http.StatusOK {
		t.Errorf("verify unavailable: %d", code)
	}
}

type stubVerification struct{ res verification.Result }

func (s stubVerification) Verify(context.Context, string) verification.Result { return s.res }

func TestVerifyDistinguishesUnavailableFromInvalid(t *testing.T) {
	for _, tc := range []struct {
		reason verification.Reason
		want   int
	}{
		{verification.ReasonRevoked, http.StatusOK},
		{verification.ReasonUntrustedIssuer, http.StatusOK},
		{verification.ReasonUnavailable, http.StatusServiceUnavailable},
	} {
		api := httpapi.API{CredentialVerification: stubVerification{verification.Result{Reason: tc.reason}}}
		srv := httptest.NewServer(httpapi.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), api))
		resp, err := http.Post(srv.URL+"/v1/credentials/verify", "application/json", strings.NewReader(`{"credential":"x"}`))
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		srv.Close()

		if resp.StatusCode != tc.want || body["valid"] != false || body["reason"] != string(tc.reason) {
			t.Errorf("%s: status=%d body=%v, want %d with valid=false", tc.reason, resp.StatusCode, body, tc.want)
		}
	}
}

// The same endpoints carry any registered credential type: here a membership,
// with a policy that only discloses the tier.
func TestNonKYCCredentialTypeEndToEnd(t *testing.T) {
	e := newEnv(t, true)
	token := e.issueCredential(t, `{"subject":"user-9","credential_type":"Membership","outcome":"approved","claims":{"tier":"gold","member_since":2024}}`)

	code, res := e.post(t, "/v1/credentials/verify", `{"credential":"`+token+`"}`)
	if code != http.StatusOK || res["valid"] != true || res["credential_type"] != membershipType {
		t.Fatalf("verify = %d %v", code, res)
	}
	claims := res["claims"].(map[string]any)
	if len(claims) != 1 || claims["tier"] != "gold" {
		t.Errorf("claims = %v, want only the disclosed tier", claims)
	}

	// A policy the credential does not meet.
	silver := e.issueCredential(t, `{"subject":"user-10","credential_type":"Membership","outcome":"approved","claims":{"tier":"silver"}}`)
	_, res = e.post(t, "/v1/credentials/verify", `{"credential":"`+silver+`"}`)
	if res["valid"] != false || res["reason"] != "policy_not_satisfied" {
		t.Fatalf("silver verify = %v", res)
	}
}
