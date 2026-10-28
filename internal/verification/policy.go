// Package verification applies a relying application's acceptance policy on
// top of cryptographic credential verification, and checks issuer trust and
// credential status on chain.
package verification

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

// disclosed returns the claims to hand back to the application.
func (p Policy) disclosed(claims map[string]any) map[string]any {
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
