// Package challenge is the use case behind the challenge-response protocol
// (docs/challenge_response_protocol.md): a relying application creates a
// challenge, a holder answers it with a credential and a signature, and the
// application reads the verdict. Credential verification itself is delegated to the verification
// service; this package adds the challenge lifecycle and the holder binding.
package challenge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/verification"
	domainchallenge "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
)

// Rejection reasons added by this protocol, alongside the credential
// verification reasons.
const (
	ReasonWrongCredentialType verification.Reason = "wrong_credential_type"
	ReasonHolderBinding       verification.Reason = "holder_binding_failed"
	ReasonClaimUnavailable    verification.Reason = "claim_unavailable"

	// MaxOpenChallenges limits the in-memory challenge store, so unauthenticated
	// challenge creation cannot exhaust memory.
	MaxOpenChallenges = 10_000
)

// Store keeps challenges and their state. Consume must be atomic: of any number
// of concurrent calls for one challenge, exactly one succeeds. Errors are the
// domain's ErrNotFound, ErrExpired, ErrAlreadyUsed and ErrStoreFull.
type Store interface {
	Create(ctx context.Context, s domainchallenge.Session) error
	Get(ctx context.Context, id string) (domainchallenge.Session, error)
	Consume(ctx context.Context, id string, now time.Time) (domainchallenge.Challenge, error)
	Complete(ctx context.Context, id string, v domainchallenge.Verdict) error
}

// Verifier verifies a credential token, returning its subject and disclosable
// claims when valid. verification.Service implements it.
type Verifier interface {
	Verify(ctx context.Context, token string) verification.Result
}

// CreateRequest is what a relying application asks for.
type CreateRequest struct {
	Audience       string
	CredentialType string
	Claims         []string
	CallbackURL    string
}

// Created is a new challenge and the secret with which only its creator can
// read the verdict.
type Created struct {
	Challenge    domainchallenge.Challenge
	ResultSecret string
}

// View is a challenge as the holder's wallet sees it.
type View struct {
	Challenge domainchallenge.Challenge
	// Completed means the challenge was already answered.
	Completed bool
}

// Service runs the challenge-response protocol.
type Service struct {
	store    Store
	verifier Verifier
	ttl      time.Duration
	now      func() time.Time
}

// Option customizes a Service.
type Option func(*Service)

// WithClock overrides the wall clock.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// NewService returns a Service whose challenges live for ttl.
func NewService(store Store, verifier Verifier, ttl time.Duration, opts ...Option) (*Service, error) {
	if store == nil || verifier == nil {
		return nil, errors.New("challenge: store and verifier are required")
	}
	if ttl <= 0 {
		return nil, errors.New("challenge: challenge ttl must be positive")
	}
	s := &Service{store: store, verifier: verifier, ttl: ttl, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// CreateChallenge validates the request and opens a challenge. Errors wrap
// domain.ErrInvalidRequest for a bad request and domain.ErrStoreFull when too
// many challenges are open.
func (s *Service) CreateChallenge(ctx context.Context, req CreateRequest) (Created, error) {
	id, err := randomToken(16)
	if err != nil {
		return Created{}, err
	}
	secret, err := randomToken(32)
	if err != nil {
		return Created{}, err
	}
	c, err := domainchallenge.NewChallenge(id, req.Audience, req.CredentialType, req.Claims, req.CallbackURL, s.now().Add(s.ttl))
	if err != nil {
		return Created{}, err
	}
	if err := s.store.Create(ctx, domainchallenge.Session{Challenge: c, SecretHash: sha256.Sum256([]byte(secret))}); err != nil {
		return Created{}, err
	}
	return Created{Challenge: c, ResultSecret: secret}, nil
}

// Challenge returns what the wallet needs to ask for consent, or
// domain.ErrNotFound or domain.ErrExpired.
func (s *Service) GetChallenge(ctx context.Context, id string) (View, error) {
	sess, err := s.store.Get(ctx, id)
	if err != nil {
		return View{}, err
	}
	if !s.now().Before(sess.Challenge.ExpiresAt) {
		return View{}, domainchallenge.ErrExpired
	}
	return View{Challenge: sess.Challenge, Completed: sess.Used}, nil
}

// RespondChallenge answers a challenge with a credential and the holder's signature, and
// returns the verdict, which is also stored for the challenge's creator.
//
// The challenge is consumed before anything else is checked, so each challenge
// gets one attempt whatever its outcome. The only errors that leave it unspent
// are a malformed request (domain.ErrInvalidRequest) and a challenge that does
// not exist, has expired or was already used.
func (s *Service) RespondChallenge(ctx context.Context, id, token string, holderSignature []byte) (domainchallenge.Verdict, error) {
	if token == "" || len(holderSignature) != ed25519.SignatureSize {
		return domainchallenge.Verdict{}, fmt.Errorf("%w: a credential and a 64-byte signature are required", domainchallenge.ErrInvalidRequest)
	}
	c, err := s.store.Consume(ctx, id, s.now())
	if err != nil {
		return domainchallenge.Verdict{}, err
	}
	verdict := s.decide(ctx, c, token, holderSignature)
	if err := s.store.Complete(ctx, id, verdict); err != nil {
		return domainchallenge.Verdict{}, err
	}
	return verdict, nil
}

func (s *Service) decide(ctx context.Context, c domainchallenge.Challenge, token string, signature []byte) domainchallenge.Verdict {
	res := s.verifier.Verify(ctx, token)
	if !res.Valid {
		if res.Reason == verification.ReasonUnavailable {
			return domainchallenge.Verdict{Status: domainchallenge.StatusUnavailable, Reason: string(res.Reason)}
		}
		return rejected(res.Reason)
	}
	if res.CredentialType != c.CredentialType {
		return rejected(ReasonWrongCredentialType)
	}
	if err := domainchallenge.VerifyHolder(c, token, res.Subject, signature); err != nil {
		return rejected(ReasonHolderBinding)
	}
	claims := make(map[string]any, len(c.Claims))
	for _, name := range c.Claims {
		value, ok := res.Claims[name]
		if !ok {
			return rejected(ReasonClaimUnavailable)
		}
		claims[name] = value
	}
	return domainchallenge.Verdict{
		Status:              domainchallenge.StatusVerified,
		Issuer:              res.Issuer,
		CredentialType:      res.CredentialType,
		Claims:              claims,
		CredentialExpiresAt: res.ExpiresAt,
	}
}

func rejected(reason verification.Reason) domainchallenge.Verdict {
	return domainchallenge.Verdict{Status: domainchallenge.StatusRejected, Reason: string(reason)}
}

// Result returns the verdict for a challenge to the party holding its secret.
// An unknown challenge and a wrong secret are indistinguishable
// (domain.ErrNotFound). Before an answer the status is pending, or expired
// once the challenge's time is up.
func (s *Service) GetChallengeResult(ctx context.Context, id, secret string) (domainchallenge.Verdict, error) {
	sess, err := s.store.Get(ctx, id)
	if err != nil {
		return domainchallenge.Verdict{}, err
	}
	hash := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(hash[:], sess.SecretHash[:]) != 1 {
		return domainchallenge.Verdict{}, domainchallenge.ErrNotFound
	}
	switch {
	case sess.Verdict != nil:
		return *sess.Verdict, nil
	case !s.now().Before(sess.Challenge.ExpiresAt):
		return domainchallenge.Verdict{Status: domainchallenge.StatusExpired}, nil
	}
	return domainchallenge.Verdict{Status: domainchallenge.StatusPending}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("challenge: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
