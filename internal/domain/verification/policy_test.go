package verification
import "testing"

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

func TestAcceptsIssuer(t *testing.T) {
	if !(Policy{}).AcceptsIssuer("did:example:anyone") {
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
		if got := p.AcceptsIssuer(issuer); got != want {
			t.Errorf("acceptsIssuer(%q) = %v, want %v", issuer, got, want)
		}
	}
}

