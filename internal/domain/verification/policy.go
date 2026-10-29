// Package verification defines the domain rules a relying application applies
// on top of cryptographic credential verification: which credential types it
// accepts, which issuers it accepts them from, which claims must hold, and which
// claims it wants disclosed. The application layer (internal/application/
// verification) applies these policies and adds the on-chain checks.
package verification

import "slices"

// Requirement is a claim that must have an exact value.
type Requirement struct {
	Claim string
	// Equals is the required value: a bool, string or number.
	Equals any
}

// Policy is a relying application's rules for one credential type. A verifier
// accepts only the credential types it has a Policy for.
type Policy struct {
	// CredentialType is the credential_type this policy governs.
	CredentialType string
	// Require lists the claims that must all match.
	Require []Requirement
	// Disclose lists the claims returned to the application when verification
	// succeeds. Nil returns every claim; use it to return only what the
	// application needs (data minimization).
	Disclose []string
	// AcceptedIssuers lists the issuers (their "iss" identifiers) whose
	// credentials of this type the application accepts. The registry says an
	// issuer is trusted in general, not for which credential types, so this is
	// how an application limits each type to the issuers it expects: a trusted
	// ticketing issuer must not be able to mint a KYC credential.
	//
	// Empty accepts any issuer the registry trusts. Set it whenever more than
	// one issuer is trusted.
	AcceptedIssuers []string
}

// AcceptsIssuer reports whether credentials of this type from issuer are
// acceptable. Issuer identifiers are compared exactly.
func (p Policy) AcceptsIssuer(issuer string) bool {
	return len(p.AcceptedIssuers) == 0 || slices.Contains(p.AcceptedIssuers, issuer)
}

// Satisfied reports whether the claims meet every requirement. A missing claim
// never satisfies a requirement.
func (p Policy) Satisfied(claims map[string]any) bool {
	for _, r := range p.Require {
		got, ok := claims[r.Claim]
		if !ok || !valuesEqual(got, r.Equals) {
			return false
		}
	}
	return true
}

// Disclosed returns the claims to hand back to the application: all of them when
// Disclose is nil, otherwise only the listed ones. The result is a new map.
func (p Policy) Disclosed(claims map[string]any) map[string]any {
	out := make(map[string]any, len(claims))
	if p.Disclose == nil {
		for k, v := range claims {
			out[k] = v
		}
		return out
	}
	for _, k := range p.Disclose {
		if v, ok := claims[k]; ok {
			out[k] = v
		}
	}
	return out
}

// valuesEqual compares two claim values. Numbers are compared as float64,
// matching how JSON decodes them; values of different kinds are never equal.
func valuesEqual(a, b any) bool {
	if fa, ok := toFloat(a); ok {
		fb, ok := toFloat(b)
		return ok && fa == fb
	}
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}
