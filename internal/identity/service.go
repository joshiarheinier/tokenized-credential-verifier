// Package identity simulates KYC outcomes for local development. It must not
// be wired up as a production approval mechanism.
package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/joshia/tokenized-identity-kyc/internal/credential"
)

// Outcome is a simulated KYC decision.
type Outcome string

const (
	OutcomeApproved Outcome = "approved"
	OutcomeRejected Outcome = "rejected"
)

const maxSubjectLen = 256

var countryRE = regexp.MustCompile(`^[A-Z]{2}$`)

var (
	ErrInvalidRequest = errors.New("identity: invalid request")
	ErrNotFound       = errors.New("identity: kyc result not found")
	ErrNotApproved    = errors.New("identity: kyc result not approved")
	ErrAlreadyUsed    = errors.New("identity: kyc result already used")
)

// SimulationRequest describes the simulated applicant and the decision to
// produce. Over18 and Country are ignored for rejected outcomes.
type SimulationRequest struct {
	Subject string
	Outcome Outcome
	Over18  bool
	Country string
}

// Result is a stored simulated KYC decision.
type Result struct {
	ID      string
	Subject string
	Outcome Outcome
	Claims  credential.KYCClaims
	used    bool
}

// Service stores simulated KYC results in memory.
type Service struct {
	mu      sync.Mutex
	results map[string]*Result
}

func NewService() *Service {
	return &Service{results: make(map[string]*Result)}
}

// Simulate validates the request and records a KYC decision.
func (s *Service) Simulate(_ context.Context, req SimulationRequest) (Result, error) {
	subject := strings.TrimSpace(req.Subject)
	if subject == "" || len(subject) > maxSubjectLen {
		return Result{}, fmt.Errorf("%w: subject must be 1-%d characters", ErrInvalidRequest, maxSubjectLen)
	}
	r := Result{Subject: subject, Outcome: req.Outcome}
	switch req.Outcome {
	case OutcomeApproved:
		if !countryRE.MatchString(req.Country) {
			return Result{}, fmt.Errorf("%w: country must be an ISO 3166-1 alpha-2 code such as ID", ErrInvalidRequest)
		}
		r.Claims = credential.KYCClaims{KYCVerified: true, Over18: req.Over18, Country: req.Country}
	case OutcomeRejected:
	default:
		return Result{}, fmt.Errorf("%w: outcome must be approved or rejected", ErrInvalidRequest)
	}

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Result{}, fmt.Errorf("identity: generate id: %w", err)
	}
	r.ID = base64.RawURLEncoding.EncodeToString(b[:])

	s.mu.Lock()
	s.results[r.ID] = &r
	s.mu.Unlock()
	return r, nil
}

// ConsumeApproval returns the approval for a KYC result exactly once.
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
	return credential.Approval{Subject: r.Subject, Claims: r.Claims}, nil
}
