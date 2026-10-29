package verification

import (
	"context"
	"testing"

	domainverification "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/verification"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
)

func TestVerifyAppliesPolicyPerType(t *testing.T) {
	f := newFixture(t)

	// A type with no policy is not accepted by this verifier at all.
	noPolicy := NewService(credentialVerifier(t, f), nil)
	if res := noPolicy.Verify(context.Background(), f.token); res.Valid || res.Reason != ReasonUnsupported {
		t.Fatalf("Valid=%v Reason=%q, want rejected as unsupported", res.Valid, res.Reason)
	}

	// A policy the credential does not meet.
	strict := NewService(credentialVerifier(t, f), []domainverification.Policy{{
		CredentialType: testType,
		Require:        []domainverification.Requirement{{Claim: "tier", Equals: "platinum"}},
	}})
	if res := strict.Verify(context.Background(), f.token); res.Valid || res.Reason != ReasonPolicyNotSatisfied {
		t.Fatalf("Valid=%v Reason=%q, want policy_not_satisfied", res.Valid, res.Reason)
	}

	// Only the claims the application asked for come back.
	minimal := NewService(credentialVerifier(t, f), []domainverification.Policy{{
		CredentialType: testType,
		Require:        []domainverification.Requirement{{Claim: "active", Equals: true}},
		Disclose:       []string{"active"},
	}})
	res := minimal.Verify(context.Background(), f.token)
	if !res.Valid || len(res.Claims) != 1 || res.Claims["active"] != true {
		t.Fatalf("Valid=%v Claims=%v, want only the active claim", res.Valid, res.Claims)
	}
}

func TestIssuerAllowListIsPerType(t *testing.T) {
	f := newFixture(t)
	verify := func(p Policy) Result {
		return NewService(credentialVerifier(t, f), []domainverification.Policy{p}).Verify(context.Background(), f.token)
	}
	base := domainverification.Policy{CredentialType: testType, Require: []domainverification.Requirement{{Claim: "active", Equals: true}}}

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
	svc := NewService(credentialVerifier(t, f), []domainverification.Policy{{
		CredentialType:  testType,
		AcceptedIssuers: []string{"did:example:someone-else"},
	}}, WithBlockchainClient(f.reg))

	if res := svc.Verify(context.Background(), f.token); res.Reason != ReasonUntrustedIssuer {
		t.Fatalf("Reason = %q, want untrusted_issuer, not verification_unavailable", res.Reason)
	}
}
