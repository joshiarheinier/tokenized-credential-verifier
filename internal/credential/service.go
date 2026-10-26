package credential

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
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

// Service issues credentials for approved KYC results.
type Service struct {
	signer    *Signer
	approvals ApprovalSource
	ttl       time.Duration
	now       func() time.Time
}

// NewService returns an issuing Service. now may be nil to use the wall clock.
func NewService(signer *Signer, approvals ApprovalSource, ttl time.Duration, now func() time.Time) (*Service, error) {
	if signer == nil || approvals == nil {
		return nil, errors.New("credential: signer and approval source are required")
	}
	if ttl <= 0 {
		return nil, errors.New("credential: ttl must be positive")
	}
	if now == nil {
		now = time.Now
	}
	return &Service{signer: signer, approvals: approvals, ttl: ttl, now: now}, nil
}

// IssueFromApproval consumes the approval with the given id and signs a
// credential for it. Errors from the approval source are returned unchanged.
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
