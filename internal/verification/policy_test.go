package verification

import (
	"context"
	"testing"

	"github.com/joshiarheinier/tokenized-credential-verifier/pkg/connector/blockchain"
)

func TestPolicySatisfied(t *testing.T) {
	p := Policy{CredentialType: "T", Require: []Requirement{
		{Claim: "active", Equals: true},
		{Claim: "tier", Equals: "gold"},
		{Claim: "seats", Equals: 4},
	}}
	good := map[string]any{"active": true, "tier": "gold", "seats": 4.0} // JSON numbers decode to float64
	if !p.Satisfied(good) {
		t.Fatal("matching claims rejected")
	}
	for name, claims := range map[string]map[string]any{
		"wrong bool":   {"active": false, "tier": "gold", "seats": 4.0},
		"wrong string": {"active": true, "tier": "silver", "seats": 4.0},
		"wrong number": {"active": true, "tier": "gold", "seats": 5.0},
		"missing":      {"active": true, "tier": "gold"},
		"wrong kind":   {"active": "true", "tier": "gold", "seats": 4.0},
		"nil claims":   nil,
	} {
		if p.Satisfied(claims) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPolicyWithNoRequirementsAcceptsAnyClaims(t *testing.T) {
	if !(Policy{CredentialType: "T"}).Satisfied(map[string]any{"x": 1}) {
		t.Fatal("a policy with no requirements should accept (it only scopes the type)")
	}
}

func TestDisclosure(t *testing.T) {
	claims := map[string]any{"tier": "gold", "active": true}

	all := Policy{}.disclosed(claims)
	if len(all) != 2 {
		t.Errorf("nil Disclose returned %v, want every claim", all)
	}
	all["tier"] = "mutated" // the result must not alias the credential's claims
	if claims["tier"] != "gold" {
		t.Error("disclosed claims alias the original map")
	}

	only := Policy{Disclose: []string{"active", "not-present"}}.disclosed(claims)
	if len(only) != 1 || only["active"] != true {
		t.Errorf("Disclose=[active] returned %v", only)
	}
	if none := (Policy{Disclose: []string{}}).disclosed(claims); len(none) != 0 {
		t.Errorf("empty (non-nil) Disclose returned %v, want no claims", none)
	}
}

func TestVerifyAppliesPolicyPerType(t *testing.T) {
	f := newFixture(t)

	// A type with no policy is not accepted by this verifier at all.
	noPolicy := NewService(credentialVerifier(t, f), nil)
	if res := noPolicy.Verify(context.Background(), f.token); res.Valid || res.Reason != ReasonUnsupported {
		t.Fatalf("Valid=%v Reason=%q, want rejected as unsupported", res.Valid, res.Reason)
	}

	// A policy the credential does not meet.
	strict := NewService(credentialVerifier(t, f), []Policy{{
		CredentialType: testType,
		Require:        []Requirement{{Claim: "tier", Equals: "platinum"}},
	}})
	if res := strict.Verify(context.Background(), f.token); res.Valid || res.Reason != ReasonPolicyNotSatisfied {
		t.Fatalf("Valid=%v Reason=%q, want policy_not_satisfied", res.Valid, res.Reason)
	}

	// Only the claims the application asked for come back.
	minimal := NewService(credentialVerifier(t, f), []Policy{{
		CredentialType: testType,
		Require:        []Requirement{{Claim: "active", Equals: true}},
		Disclose:       []string{"active"},
	}})
	res := minimal.Verify(context.Background(), f.token)
	if !res.Valid || len(res.Claims) != 1 || res.Claims["active"] != true {
		t.Fatalf("Valid=%v Claims=%v, want only the active claim", res.Valid, res.Claims)
	}
}

func TestAcceptsIssuer(t *testing.T) {
	if !(Policy{}).acceptsIssuer("did:example:anyone") {
		t.Error("an empty allow-list should accept any issuer the registry trusts")
	}
	p := Policy{AcceptedIssuers: []string{"did:example:a", "did:example:b"}}
	for issuer, want := range map[string]bool{
		"did:example:a":   true,
		"did:example:b":   true,
		"did:example:c":   false,
		"did:example:A":   false, // exact match only
		"did:example:a ":  false,
		"":                false,
		"did:example:a/x": false,
	} {
		if got := p.acceptsIssuer(issuer); got != want {
			t.Errorf("acceptsIssuer(%q) = %v, want %v", issuer, got, want)
		}
	}
}

func TestIssuerAllowListIsPerType(t *testing.T) {
	f := newFixture(t)
	verify := func(p Policy) Result {
		return NewService(credentialVerifier(t, f), []Policy{p}).Verify(context.Background(), f.token)
	}
	base := Policy{CredentialType: testType, Require: []Requirement{{Claim: "active", Equals: true}}}

	// The issuer is trusted by the verifier, but this application only expects
	// another issuer for this type.
	other := base
	other.AcceptedIssuers = []string{"did:example:someone-else"}
	if res := verify(other); res.Valid || res.Reason != ReasonUntrustedIssuer {
		t.Fatalf("Valid=%v Reason=%q, want untrusted_issuer for an issuer not on the list", res.Valid, res.Reason)
	}

	listed := base
	listed.AcceptedIssuers = []string{"did:example:someone-else", issuerName}
	if res := verify(listed); !res.Valid {
		t.Fatalf("Valid=false (%s), want an issuer on the list accepted", res.Reason)
	}

	if res := verify(base); !res.Valid {
		t.Fatalf("Valid=false (%s), want an empty list to accept any trusted issuer", res.Reason)
	}
}

// The allow-list is a local check: an unlisted issuer is turned away without
// the chain being consulted, so it cannot be mistaken for an outage.
func TestIssuerAllowListIsCheckedBeforeTheChain(t *testing.T) {
	f := newFixture(t)
	f.reg.issuerErr = blockchain.ErrUnavailable
	svc := NewService(credentialVerifier(t, f), []Policy{{
		CredentialType:  testType,
		AcceptedIssuers: []string{"did:example:someone-else"},
	}}, WithBlockchainClient(f.reg))

	if res := svc.Verify(context.Background(), f.token); res.Reason != ReasonUntrustedIssuer {
		t.Fatalf("Reason = %q, want untrusted_issuer, not verification_unavailable", res.Reason)
	}
}
