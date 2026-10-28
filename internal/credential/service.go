package credential

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/joshia/tokenized-identity-kyc/pkg/connector/blockchain"
)

// ApprovalSource hands out simulated KYC approvals. ConsumeApproval must
// return each approval at most once.
type ApprovalSource interface {
	ConsumeApproval(ctx context.Context, id string) (Approval, error)
}

// Issued is a newly issued credential.
type Issued struct {
	Token     string
	ExpiresAt time.Time
}

// BlockchainClient is the part of the Solana connector's client
// (pkg/connector/blockchain.Client) that issuance needs: recording an issued
// credential in the on-chain registry so verifiers can later check its status.
// RegisterCredential must be idempotent for repeated identical calls.
type BlockchainClient interface {
	RegisterCredential(ctx context.Context, issuerID, credentialRef [32]byte, expiresAt time.Time) (blockchain.WriteResult, error)
}

// Service issues credentials for approved KYC results.
type Service struct {
	signer    *Signer
	approvals ApprovalSource
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

// NewService returns an issuing Service. now may be nil to use the wall clock.
func NewService(signer *Signer, approvals ApprovalSource, ttl time.Duration, now func() time.Time, opts ...ServiceOption) (*Service, error) {
	if signer == nil || approvals == nil {
		return nil, errors.New("credential: signer and approval source are required")
	}
	if ttl <= 0 {
		return nil, errors.New("credential: ttl must be positive")
	}
	if now == nil {
		now = time.Now
	}
	s := &Service{signer: signer, approvals: approvals, ttl: ttl, now: now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// IssueFromApproval consumes the approval with the given id and signs a
// credential for it. Errors from the approval source are returned unchanged.
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
	id, err := randomID()
	if err != nil {
		return Issued{}, err
	}
	now := s.now()
	exp := now.Add(s.ttl)
	if s.chain != nil {
		_, err := s.chain.RegisterCredential(ctx,
			blockchain.IssuerID(s.signer.IssuerID()),
			blockchain.CredentialRef(id),
			time.Unix(exp.Unix(), 0))
		if err != nil {
			return Issued{}, fmt.Errorf("credential: register: %w", err)
		}
	}
	token, err := s.signer.Sign(Claims{
		Subject:        a.Subject,
		ID:             id,
		IssuedAt:       now.Unix(),
		ExpiresAt:      exp.Unix(),
		CredentialType: TypeKYCStatus,
		KYC:            a.Claims,
	})
	if err != nil {
		return Issued{}, err
	}
	return Issued{Token: token, ExpiresAt: time.Unix(exp.Unix(), 0).UTC()}, nil
}

// randomID returns an unguessable 128-bit identifier. It is random rather than
// derived from user data so it can later serve as an on-chain opaque reference.
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("credential: generate id: %w", err)
	}
	return b64.EncodeToString(b[:]), nil
}
