package challenge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/verification"
	domain "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
)

var now = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)

const (
	audience = "http://localhost:9090"
	token    = "credential-token"
)

// mapStore is the smallest Store that keeps Consume atomic.
type mapStore struct {
	mu sync.Mutex
	m  map[string]*domain.Session
}

func (s *mapStore) Create(_ context.Context, sess domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]*domain.Session{}
	}
	s.m[sess.Challenge.ID] = &sess
	return nil
}

func (s *mapStore) Get(_ context.Context, id string) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess := s.m[id]; sess != nil {
		return *sess, nil
	}
	return domain.Session{}, domain.ErrNotFound
}

func (s *mapStore) Consume(_ context.Context, id string, at time.Time) (domain.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.m[id]
	switch {
	case sess == nil:
		return domain.Challenge{}, domain.ErrNotFound
	case sess.Used:
		return domain.Challenge{}, domain.ErrAlreadyUsed
	case !at.Before(sess.Challenge.ExpiresAt):
		return domain.Challenge{}, domain.ErrExpired
	}
	sess.Used = true
	return sess.Challenge, nil
}

func (s *mapStore) Complete(_ context.Context, id string, v domain.Verdict) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id].Verdict = &v
	return nil
}

// fakeVerifier answers for the one credential the test uses.
type fakeVerifier struct {
	result verification.Result
	calls  int
}

func (f *fakeVerifier) Verify(context.Context, string) verification.Result {
	f.calls++
	return f.result
}

type fixture struct {
	svc      *Service
	verifier *fakeVerifier
	holder   ed25519.PrivateKey
	clock    *time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	v := &fakeVerifier{result: verification.Result{
		Valid:          true,
		Issuer:         "did:example:issuer",
		Subject:        domain.HolderID(pub),
		CredentialType: "KYCStatus",
		ExpiresAt:      now.Add(24 * time.Hour),
		Claims:         map[string]any{"kyc_verified": true, "over_18": true, "country": "ID"},
	}}
	svc, err := NewService(&mapStore{}, v, 5*time.Minute, WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, verifier: v, holder: priv, clock: &clock}
}

func (f *fixture) create(t *testing.T) Created {
	t.Helper()
	c, err := f.svc.CreateChallenge(context.Background(), CreateRequest{
		Audience: audience, CredentialType: "KYCStatus", Claims: []string{"over_18"}, CallbackURL: audience + "/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) sign(c domain.Challenge, tok string) []byte {
	return ed25519.Sign(f.holder, []byte(domain.Message(c, tok)))
}

func TestHappyPath(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	created := f.create(t)

	view, err := f.svc.GetChallenge(ctx, created.Challenge.ID)
	if err != nil || view.Completed || view.Challenge.Audience != audience {
		t.Fatalf("Challenge = %+v, %v", view, err)
	}
	if res, err := f.svc.GetChallengeResult(ctx, created.Challenge.ID, created.ResultSecret); err != nil || res.Status != domain.StatusPending {
		t.Fatalf("Result before answering = %+v, %v, want pending", res, err)
	}

	verdict, err := f.svc.RespondChallenge(ctx, created.Challenge.ID, token, f.sign(created.Challenge, token))
	if err != nil || verdict.Status != domain.StatusVerified {
		t.Fatalf("Respond = %+v, %v, want verified", verdict, err)
	}

	res, err := f.svc.GetChallengeResult(ctx, created.Challenge.ID, created.ResultSecret)
	if err != nil || res.Status != domain.StatusVerified {
		t.Fatalf("Result = %+v, %v", res, err)
	}
	// Only the requested claim comes back, though the credential holds three.
	if len(res.Claims) != 1 || res.Claims["over_18"] != true {
		t.Fatalf("claims = %v, want only over_18", res.Claims)
	}
	if res.Issuer != "did:example:issuer" || res.CredentialType != "KYCStatus" {
		t.Fatalf("result = %+v", res)
	}
}

func TestResponseIsRejectedWhenTheCredentialIsNotBoundToTheSigner(t *testing.T) {
	f := newFixture(t)
	created := f.create(t)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)

	verdict, err := f.svc.RespondChallenge(context.Background(), created.Challenge.ID, token,
		ed25519.Sign(stranger, []byte(domain.Message(created.Challenge, token))))
	if err != nil || verdict.Status != domain.StatusRejected || verdict.Reason != string(ReasonHolderBinding) {
		t.Fatalf("Respond = %+v, %v, want rejected with holder_binding_failed", verdict, err)
	}
	if len(verdict.Claims) != 0 {
		t.Fatalf("a rejection leaked claims: %v", verdict.Claims)
	}
}

func TestResponseOutcomesFromVerificationAndPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*verification.Result)
		want   domain.Status
		reason string
	}{
		"revoked credential": {func(r *verification.Result) { *r = verification.Result{Reason: verification.ReasonRevoked} }, domain.StatusRejected, "revoked"},
		"chain unavailable":  {func(r *verification.Result) { *r = verification.Result{Reason: verification.ReasonUnavailable} }, domain.StatusUnavailable, "verification_unavailable"},
		"another type":       {func(r *verification.Result) { r.CredentialType = "Membership" }, domain.StatusRejected, string(ReasonWrongCredentialType)},
		"claim not offered":  {func(r *verification.Result) { delete(r.Claims, "over_18") }, domain.StatusRejected, string(ReasonClaimUnavailable)},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tc.change(&f.verifier.result)
			created := f.create(t)
			verdict, err := f.svc.RespondChallenge(context.Background(), created.Challenge.ID, token, f.sign(created.Challenge, token))
			if err != nil || verdict.Status != tc.want || verdict.Reason != tc.reason {
				t.Fatalf("Respond = %+v, %v, want %s (%s)", verdict, err, tc.want, tc.reason)
			}
		})
	}
}

func TestEachChallengeGetsOneAttempt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	created := f.create(t)
	sig := f.sign(created.Challenge, token)

	if _, err := f.svc.RespondChallenge(ctx, created.Challenge.ID, token, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RespondChallenge(ctx, created.Challenge.ID, token, sig); !errors.Is(err, domain.ErrAlreadyUsed) {
		t.Fatalf("second attempt: err = %v, want ErrAlreadyUsed", err)
	}
	if f.verifier.calls != 1 {
		t.Fatalf("verifier called %d times, want 1: a spent challenge must not reach verification", f.verifier.calls)
	}
}

func TestMalformedResponsesDoNotSpendTheChallenge(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	created := f.create(t)

	for name, args := range map[string]struct {
		token string
		sig   []byte
	}{"no credential": {"", make([]byte, 64)}, "short signature": {token, make([]byte, 10)}} {
		if _, err := f.svc.RespondChallenge(ctx, created.Challenge.ID, args.token, args.sig); !errors.Is(err, domain.ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
	if _, err := f.svc.RespondChallenge(ctx, created.Challenge.ID, token, f.sign(created.Challenge, token)); err != nil {
		t.Fatalf("a good attempt after malformed ones: %v", err)
	}
}

func TestExpiredAndUnknownChallenges(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	created := f.create(t)

	if _, err := f.svc.RespondChallenge(ctx, "unknown", token, make([]byte, 64)); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown: err = %v, want ErrNotFound", err)
	}
	*f.clock = now.Add(5 * time.Minute)
	if _, err := f.svc.GetChallenge(ctx, created.Challenge.ID); !errors.Is(err, domain.ErrExpired) {
		t.Errorf("Challenge after expiry: err = %v, want ErrExpired", err)
	}
	if _, err := f.svc.RespondChallenge(ctx, created.Challenge.ID, token, f.sign(created.Challenge, token)); !errors.Is(err, domain.ErrExpired) {
		t.Errorf("Respond after expiry: err = %v, want ErrExpired", err)
	}
	if res, err := f.svc.GetChallengeResult(ctx, created.Challenge.ID, created.ResultSecret); err != nil || res.Status != domain.StatusExpired {
		t.Errorf("Result after expiry = %+v, %v, want expired", res, err)
	}
}

func TestOnlyTheCreatorCanReadTheResult(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	created := f.create(t)
	if _, err := f.svc.RespondChallenge(ctx, created.Challenge.ID, token, f.sign(created.Challenge, token)); err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{"wrong secret": "guess", "no secret": ""} {
		if _, err := f.svc.GetChallengeResult(ctx, created.Challenge.ID, secret); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
	if _, err := f.svc.GetChallengeResult(ctx, "unknown", created.ResultSecret); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown id: err = %v, want the same ErrNotFound", err)
	}
}

func TestCreateChallengeRejectsABadRequest(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.CreateChallenge(context.Background(), CreateRequest{Audience: "http://evil.example", CredentialType: "KYCStatus", Claims: []string{"over_18"}})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("err = %v, want ErrInvalidRequest", err)
	}
}

func TestNewServiceValidation(t *testing.T) {
	if _, err := NewService(nil, &fakeVerifier{}, time.Minute); err == nil {
		t.Error("nil store accepted")
	}
	if _, err := NewService(&mapStore{}, nil, time.Minute); err == nil {
		t.Error("nil verifier accepted")
	}
	if _, err := NewService(&mapStore{}, &fakeVerifier{}, 0); err == nil {
		t.Error("zero ttl accepted")
	}
}
