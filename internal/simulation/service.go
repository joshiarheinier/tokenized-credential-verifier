// Package simulation stands in for an issuer's real approval process (an
// identity check, a ticket purchase, a membership signup) during local
// development. It must not be wired up as a production approval mechanism.
package simulation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/joshia/tokenized-credential-verifier/internal/credential"
)

// Outcome is a simulated approval decision.
type Outcome string

const (
	OutcomeApproved Outcome = "approved"
	OutcomeRejected Outcome = "rejected"
)

const maxSubjectLen = 256

var (
	ErrInvalidRequest = errors.New("simulation: invalid request")
	ErrNotFound       = errors.New("simulation: approval not found")
	ErrNotApproved    = errors.New("simulation: approval was not approved")
	ErrAlreadyUsed    = errors.New("simulation: approval already used")
)

// Request describes the simulated subject and the decision to produce. For an
// approved outcome CredentialType must be a known type and Claims must match its
// schema. Both are ignored for rejected outcomes.
type Request struct {
	Subject        string
	CredentialType string
	Outcome        Outcome
	Claims         map[string]any
}

// Result is a stored simulated decision.
type Result struct {
	ID             string
	Subject        string
	CredentialType string
	Outcome        Outcome
	Claims         map[string]any
	used           bool
}

// Service stores simulated approvals in memory.
type Service struct {
	schemas *credential.Schemas

	mu      sync.Mutex
	results map[string]*Result
}

// NewService returns a Service that validates approved requests against schemas.
func NewService(schemas *credential.Schemas) *Service {
	return &Service{schemas: schemas, results: make(map[string]*Result)}
}

// Simulate validates the request and records a decision.
func (s *Service) Simulate(_ context.Context, req Request) (Result, error) {
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
		return Result{}, fmt.Errorf("simulation: generate id: %w", err)
	}
	r.ID = base64.RawURLEncoding.EncodeToString(b[:])

	s.mu.Lock()
	s.results[r.ID] = &r
	s.mu.Unlock()
	return r, nil
}

// ConsumeApproval returns the approval for a simulated decision exactly once.
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
