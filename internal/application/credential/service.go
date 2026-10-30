package credential

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
)

// ApprovalSource hands out issuance approvals. ConsumeApproval must return each
// approval at most once.
type ApprovalSource interface {
	ConsumeApproval(ctx context.Context, id string) (credential.Approval, error)
}

// Issued is a newly issued credential.
type Issued struct {
	Token     string
	ExpiresAt time.Time
}

// ErrNoRegistry means the operation needs an on-chain registry and none is configured.
var ErrNoRegistry = errors.New("credential: this operation requires an on-chain registry")

// ErrInvalidCredential means a credential presented for revocation is not a valid, unexpired credential issued by this service.
var ErrInvalidCredential = errors.New("credential: not a valid credential issued by this service")

// BlockchainClient is what issuance needs from the on-chain registry: a way to
// record an issued credential so verifiers can later check its status, to
// revoke it, and to suspend or reactivate the issuer. It is expressed in domain types (internal/domain/registry); the
// Solana client in internal/infrastructure/client/blockchain implements it.
// RegisterCredential, RevokeCredential and SetIssuerStatus must be idempotent
// for repeated identical calls; RevokeCredential must wrap registry.ErrNotFound if the
// credential was never registered.
type BlockchainClient interface {
	RegisterCredential(ctx context.Context, issuerID, credentialRef [32]byte, expiresAt time.Time) (registry.WriteResult, error)
	RevokeCredential(ctx context.Context, issuerID, credentialRef [32]byte) (registry.WriteResult, error)
	SetIssuerStatus(ctx context.Context, issuerID [32]byte, active bool) (registry.WriteResult, error)
}

// Service issues credentials for approvals from an ApprovalSource.
type Service struct {
	signer    *credential.Signer
	verifier  *credential.Verifier // trusts only signer's key; identifies credentials to revoke
	approvals ApprovalSource
	schemas   *credential.Schemas
	ttl       time.Duration
	now       func() time.Time
	chain     BlockchainClient
}

// ServiceOption customizes a Service.
type ServiceOption func(*Service)

// WithBlockchainClient makes issuance register each credential on chain through
// c before returning it. If registration fails no credential is returned: a
// credential the registry does not know about would be rejected by verifiers
// anyway.
func WithBlockchainClient(c BlockchainClient) ServiceOption {
	return func(s *Service) { s.chain = c }
}

// NewService returns an issuing Service that can issue the credential types in
// schemas. now may be nil to use the wall clock.
func NewService(signer *credential.Signer, approvals ApprovalSource, schemas *credential.Schemas, ttl time.Duration, now func() time.Time, opts ...ServiceOption) (*Service, error) {
	if signer == nil || approvals == nil || schemas == nil {
		return nil, errors.New("credential: signer, approval source and schemas are required")
	}
	if ttl <= 0 {
		return nil, errors.New("credential: ttl must be positive")
	}
	if now == nil {
		now = time.Now
	}
	verifier := credential.NewVerifier(schemas, now)
	verifier.Trust(signer.IssuerID(), signer.PublicKey())
	s := &Service{signer: signer, verifier: verifier, approvals: approvals, schemas: schemas, ttl: ttl, now: now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// IssueFromApproval consumes the approval with the given id and signs a
// credential for it. Errors from the approval source are returned unchanged.
// The approval's credential type must be known and its claims must match that
// type's schema; otherwise nothing is registered or signed.
//
// The approval is validated and consumed before anything is registered, so
// invalid requests never cost an on-chain transaction. The consequence is that
// if registration then fails the approval stays consumed and the caller must
// obtain a new one.
func (s *Service) IssueFromApproval(ctx context.Context, approvalID string) (Issued, error) {
	a, err := s.approvals.ConsumeApproval(ctx, approvalID)
	if err != nil {
		return Issued{}, err
	}
	if err := s.schemas.Validate(a.CredentialType, a.Claims); err != nil {
		return Issued{}, fmt.Errorf("credential: approval: %w", err)
	}
	id, err := randomID()
	if err != nil {
		return Issued{}, err
	}
	now := s.now()
	exp := now.Add(s.ttl)
	if s.chain != nil {
		_, err := s.chain.RegisterCredential(ctx,
			registry.IssuerID(s.signer.IssuerID()),
			registry.CredentialRef(id),
			time.Unix(exp.Unix(), 0))
		if err != nil {
			return Issued{}, fmt.Errorf("credential: register: %w", err)
		}
	}
	token, err := s.signer.Sign(credential.Claims{
		Subject:        a.Subject,
		ID:             id,
		IssuedAt:       now.Unix(),
		ExpiresAt:      exp.Unix(),
		CredentialType: a.CredentialType,
		Attributes:     a.Claims,
	})
	if err != nil {
		return Issued{}, err
	}
	return Issued{Token: token, ExpiresAt: time.Unix(exp.Unix(), 0).UTC()}, nil
}

// Revoke revokes, on chain, a credential this service issued. token must verify
// as an unexpired credential of this issuer, otherwise ErrInvalidCredential is
// returned and nothing is sent. Revoking an already revoked credential is a
// no-op. Revocation is permanent. It needs a BlockchainClient.
func (s *Service) Revoke(ctx context.Context, token string) error {
	if s.chain == nil {
		return ErrNoRegistry
	}
	c, err := s.verifier.Verify(token)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCredential, err)
	}
	_, err = s.chain.RevokeCredential(ctx, registry.IssuerID(c.Issuer), registry.CredentialRef(c.ID))
	return err
}

// SetIssuerActive suspends (false) or reactivates (true) this service's own
// issuer in the registry. While suspended, verifiers reject every credential it
// issued and the registry refuses new ones; reactivating undoes it. It needs a
// BlockchainClient whose registry authority key is configured, which is a
// development arrangement: a production issuer does not administer the registry.
func (s *Service) SetIssuerActive(ctx context.Context, active bool) error {
	if s.chain == nil {
		return ErrNoRegistry
	}
	_, err := s.chain.SetIssuerStatus(ctx, registry.IssuerID(s.signer.IssuerID()), active)
	return err
}

// randomID returns an unguessable 128-bit identifier. It is random rather than
// derived from user data so it can later serve as an on-chain opaque reference.
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("credential: generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
