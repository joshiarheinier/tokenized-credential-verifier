package verification

import (
	"context"
	"errors"
	"time"

	"github.com/joshia/tokenized-identity-kyc/internal/credential"
)

// Reason is a stable, coarse code explaining why a credential was rejected.
// It intentionally reveals little about the verifier's internals.
type Reason string

const (
	ReasonMalformed          Reason = "malformed"
	ReasonUnsupported        Reason = "unsupported"
	ReasonUntrustedIssuer    Reason = "untrusted_issuer"
	ReasonInvalidSignature   Reason = "invalid_signature"
	ReasonExpired            Reason = "expired"
	ReasonNotYetValid        Reason = "not_yet_valid"
	ReasonPolicyNotSatisfied Reason = "policy_not_satisfied"
)

// Result is the outcome of verifying a presented credential. Subject and
// credential id are deliberately not exposed to the relying application.
type Result struct {
	Valid          bool
	Reason         Reason
	Issuer         string
	CredentialType string
	ExpiresAt      time.Time
	Claims         credential.KYCClaims
}

// Service verifies credentials against a policy.
type Service struct {
	verifier *credential.Verifier
	policy   Policy
}

func NewService(v *credential.Verifier, p Policy) *Service {
	return &Service{verifier: v, policy: p}
}

// Verify returns a Result describing whether token is acceptable. Claims are
// only populated for valid credentials.
func (s *Service) Verify(_ context.Context, token string) Result {
	c, err := s.verifier.Verify(token)
	if err != nil {
		return Result{Reason: reasonFor(err)}
	}
	if !s.policy.Satisfied(c.KYC) {
		return Result{Reason: ReasonPolicyNotSatisfied}
	}
	return Result{
		Valid:          true,
		Issuer:         c.Issuer,
		CredentialType: c.CredentialType,
		ExpiresAt:      time.Unix(c.ExpiresAt, 0).UTC(),
		Claims:         c.KYC,
	}
}

func reasonFor(err error) Reason {
	switch {
	case errors.Is(err, credential.ErrExpired):
		return ReasonExpired
	case errors.Is(err, credential.ErrNotYetValid):
		return ReasonNotYetValid
	case errors.Is(err, credential.ErrInvalidSignature):
		return ReasonInvalidSignature
	case errors.Is(err, credential.ErrUnknownIssuer):
		return ReasonUntrustedIssuer
	case errors.Is(err, credential.ErrUnsupportedAlg),
		errors.Is(err, credential.ErrUnsupportedType),
		errors.Is(err, credential.ErrUnsupportedVersion):
		return ReasonUnsupported
	default:
		return ReasonMalformed
	}
}
