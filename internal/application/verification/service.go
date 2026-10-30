package verification

import (
	"context"
	"errors"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
	domainverification "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/verification"
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
	ReasonNotRegistered      Reason = "not_registered"
	ReasonRevoked            Reason = "revoked"
	// ReasonUnavailable means trust state could not be established (for
	// example the chain is unreachable). The credential is not accepted, but
	// this is an infrastructure failure, not a verdict on the credential.
	ReasonUnavailable Reason = "verification_unavailable"
)

// Result is the outcome of verifying a presented credential. The credential id
// is deliberately not exposed. Subject is set only for valid credentials, for the
// challenge-response protocol's holder binding; the HTTP gateway never returns it from
// the bare verify endpoint, so relying applications do not learn it.
type Result struct {
	Valid          bool
	Reason         Reason
	Issuer         string
	Subject        string
	CredentialType string
	ExpiresAt      time.Time
	Claims         map[string]any
}

// BlockchainClient is what verification needs from the on-chain registry:
// reading the issuer and credential records. It is expressed in domain types
// (internal/domain/registry); the Solana client in
// internal/infrastructure/client/blockchain implements it. Errors must wrap
// registry.ErrNotFound only when the record is known to be absent; any failure
// to establish state must be a different error, such as registry.ErrUnavailable.
type BlockchainClient interface {
	GetIssuer(ctx context.Context, id [32]byte) (registry.IssuerRecord, error)
	GetCredentialStatus(ctx context.Context, ref [32]byte) (registry.CredentialStatus, error)
}

// Service verifies credentials against per-type policies and, when a
// BlockchainClient is configured, against the issuer and credential status
// recorded on chain.
type Service struct {
	verifier *credential.Verifier
	policies map[string]domainverification.Policy // by credential type
	chain    BlockchainClient
	now      func() time.Time
}

// Option customizes a Service.
type Option func(*Service)

// WithBlockchainClient requires issuer trust and credential status to be
// confirmed on chain through c. Without it only the signature, validity period
// and policy are checked.
func WithBlockchainClient(c BlockchainClient) Option { return func(s *Service) { s.chain = c } }

// WithClock overrides the wall clock used for on-chain expiry checks.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// NewService returns a Service that accepts only the credential types it has a
// policy for; a credential of any other type is rejected as unsupported. If
// several policies name the same type the last one wins.
func NewService(v *credential.Verifier, policies []domainverification.Policy, opts ...Option) *Service {
	s := &Service{verifier: v, policies: make(map[string]domainverification.Policy, len(policies)), now: time.Now}
	for _, p := range policies {
		s.policies[p.CredentialType] = p
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Verify returns a Result describing whether token is acceptable. Claims are
// only populated for valid credentials.
//
// With a BlockchainClient configured, the signature is checked with the key the
// registry holds for the issuer, and verification fails closed: if the chain
// cannot be read, or returns something unusable, the result is ReasonUnavailable
// and the credential is not accepted.
func (s *Service) Verify(ctx context.Context, token string) Result {
	c, reason := s.authenticate(ctx, token)
	if reason != "" {
		return Result{Reason: reason}
	}
	policy, ok := s.policies[c.CredentialType]
	if !ok {
		return Result{Reason: ReasonUnsupported}
	}
	// Cheap local checks first: who issued it, then what it says. Neither
	// needs the chain.
	if !policy.AcceptsIssuer(c.Issuer) {
		return Result{Reason: ReasonUntrustedIssuer}
	}
	if !policy.Satisfied(c.Attributes) {
		return Result{Reason: ReasonPolicyNotSatisfied}
	}
	if s.chain != nil {
		if reason := s.checkOnChain(ctx, c); reason != "" {
			return Result{Reason: reason}
		}
	}
	return Result{
		Valid:          true,
		Issuer:         c.Issuer,
		Subject:        c.Subject,
		CredentialType: c.CredentialType,
		ExpiresAt:      time.Unix(c.ExpiresAt, 0).UTC(),
		Claims:         policy.Disclosed(c.Attributes),
	}
}

// authenticate verifies the signature and returns the claims, or the rejection
// reason. With a BlockchainClient the key must be the one registered on chain
// for an active issuer; otherwise it is one of the verifier's trusted keys.
func (s *Service) authenticate(ctx context.Context, token string) (*credential.Claims, Reason) {
	if s.chain == nil {
		c, err := s.verifier.Verify(token)
		if err != nil {
			return nil, reasonFor(err)
		}
		return c, ""
	}

	name, err := credential.UnverifiedIssuer(token)
	if err != nil {
		return nil, ReasonMalformed
	}

	issuer, err := s.chain.GetIssuer(ctx, registry.IssuerID(name))
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return nil, ReasonUntrustedIssuer
	case err != nil:
		return nil, ReasonUnavailable
	case !issuer.Active:
		return nil, ReasonUntrustedIssuer
	}
	c, err := s.verifier.VerifyIssuedBy(token, name, issuer.SigningKey)
	if err != nil {
		return nil, reasonFor(err)
	}

	return c, ""
}

// checkOnChain returns the rejection reason, or "" if the chain confirms the
// credential is registered by its issuer, active and unexpired.
func (s *Service) checkOnChain(ctx context.Context, c *credential.Claims) Reason {
	issuerID := registry.IssuerID(c.Issuer)
	status, err := s.chain.GetCredentialStatus(ctx, registry.CredentialRef(c.ID))
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return ReasonNotRegistered
	case err != nil:
		return ReasonUnavailable
	}
	switch {
	case status.IssuerID != issuerID:
		return ReasonNotRegistered
	case status.State == registry.CredentialRevoked:
		return ReasonRevoked
	case status.State != registry.CredentialActive:
		return ReasonUnavailable
	case !s.now().Before(status.ExpiresAt):
		return ReasonExpired
	}
	return ""
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
