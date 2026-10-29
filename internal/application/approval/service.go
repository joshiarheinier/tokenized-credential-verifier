package approval

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
)

// Outcome is an approval decision.
type Outcome string

const (
	OutcomeApproved Outcome = "approved"
	OutcomeRejected Outcome = "rejected"
)

const maxSubjectLen = 256

var (
	ErrInvalidRequest = errors.New("approval: invalid request")
	ErrNotFound       = errors.New("approval: not found")
	ErrNotApproved    = errors.New("approval: was not approved")
	ErrAlreadyUsed    = errors.New("approval: already used")
)

// Request describes the subject and the decision to record. For an
// approved outcome CredentialType must be a known type and Claims must match its
// schema. Both are ignored for rejected outcomes.
type Request struct {
	Subject        string
	CredentialType string
	Outcome        Outcome
	Claims         map[string]any
}

// Result is a stored decision.
type Result struct {
	ID             string
	Subject        string
	CredentialType string
	Outcome        Outcome
	Claims         map[string]any
	used           bool
}

// Service stores approval decisions in memory.
type Service struct {
	schemas *credential.Schemas

	mu      sync.Mutex
	results map[string]*Result
}

// NewService returns a Service that validates approved requests against schemas.
func NewService(schemas *credential.Schemas) *Service {
	return &Service{schemas: schemas, results: make(map[string]*Result)}
}

// Record validates the request and records a decision.
func (s *Service) Record(_ context.Context, req Request) (Result, error) {
	subject := strings.TrimSpace(req.Subject)
	if subject == "" || len(subject) > maxSubjectLen {
		return Result{}, fmt.Errorf("%w: subject must be 1-%d characters", ErrInvalidRequest, maxSubjectLen)
	}
	r := Result{Subject: subject, Outcome: req.Outcome}
	switch req.Outcome {
	case OutcomeApproved:
		if err := s.schemas.Validate(req.CredentialType, req.Claims); err != nil {
			return Result{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
		r.CredentialType = req.CredentialType
		r.Claims = maps.Clone(req.Claims)
	case OutcomeRejected:
	default:
		return Result{}, fmt.Errorf("%w: outcome must be approved or rejected", ErrInvalidRequest)
	}

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Result{}, fmt.Errorf("approval: generate id: %w", err)
	}
	r.ID = base64.RawURLEncoding.EncodeToString(b[:])

	s.mu.Lock()
	s.results[r.ID] = &r
	s.mu.Unlock()
	return r, nil
}

// ConsumeApproval returns the approval for a recorded decision exactly once.
func (s *Service) ConsumeApproval(_ context.Context, id string) (credential.Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[id]
	switch {
	case !ok:
		return credential.Approval{}, ErrNotFound
	case r.Outcome != OutcomeApproved:
		return credential.Approval{}, ErrNotApproved
	case r.used:
		return credential.Approval{}, ErrAlreadyUsed
	}
	r.used = true
	return credential.Approval{Subject: r.Subject, CredentialType: r.CredentialType, Claims: maps.Clone(r.Claims)}, nil
}
