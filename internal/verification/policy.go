// Package verification applies an application's acceptance policy on top of
// cryptographic credential verification.
package verification

import "github.com/joshia/tokenized-identity-kyc/internal/credential"

// Policy lists the claims a relying application requires.
type Policy struct {
	RequireKYCVerified bool
	RequireOver18      bool
}

// DefaultPolicy requires a verified KYC status.
var DefaultPolicy = Policy{RequireKYCVerified: true}

// Satisfied reports whether the claims meet the policy.
func (p Policy) Satisfied(c credential.KYCClaims) bool {
	if p.RequireKYCVerified && !c.KYCVerified {
		return false
	}
	if p.RequireOver18 && !c.Over18 {
		return false
	}
	return true
}
