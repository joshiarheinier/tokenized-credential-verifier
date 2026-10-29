package approval

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
)

const testType = "TestPass"

func testSchemas(t *testing.T) *credential.Schemas {
	t.Helper()
	s, err := credential.NewSchemas(credential.Schema{
		Type: testType,
		Fields: []credential.Field{
			{Name: "tier", Kind: credential.String, Required: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func approved(claims map[string]any) Request {
	return Request{Subject: "u", CredentialType: testType, Outcome: OutcomeApproved, Claims: claims}
}

func TestConsumeApprovalOnlyOnceUnderConcurrency(t *testing.T) {
	s := NewService(testSchemas(t))
	res, err := s.Record(context.Background(), approved(map[string]any{"tier": "gold"}))
	if err != nil {
		t.Fatal(err)
	}

	var wins, used atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch _, err := s.ConsumeApproval(context.Background(), res.ID); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrAlreadyUsed):
				used.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || used.Load() != 49 {
		t.Fatalf("wins=%d used=%d, want 1 and 49", wins.Load(), used.Load())
	}
}

func TestRejectedResultNeverYieldsApproval(t *testing.T) {
	s := NewService(testSchemas(t))
	res, _ := s.Record(context.Background(), Request{Subject: "u", Outcome: OutcomeRejected})
	if _, err := s.ConsumeApproval(context.Background(), res.ID); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err = %v, want ErrNotApproved", err)
	}
}

func TestApprovedRequestsAreValidatedAgainstTheTypeSchema(t *testing.T) {
	s := NewService(testSchemas(t))
	cases := map[string]Request{
		"unknown type":     {Subject: "u", CredentialType: "Nope", Outcome: OutcomeApproved, Claims: map[string]any{"tier": "gold"}},
		"missing claim":    approved(map[string]any{}),
		"wrong claim kind": approved(map[string]any{"tier": true}),
		"unexpected claim": approved(map[string]any{"tier": "gold", "name": "Ada"}),
		"empty subject":    {Subject: " ", CredentialType: testType, Outcome: OutcomeApproved, Claims: map[string]any{"tier": "gold"}},
		"unknown outcome":  {Subject: "u", CredentialType: testType, Outcome: "maybe"},
	}
	for name, req := range cases {
		if _, err := s.Record(context.Background(), req); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
}

func TestApprovalCarriesTypeAndClaims(t *testing.T) {
	s := NewService(testSchemas(t))
	claims := map[string]any{"tier": "gold"}
	res, err := s.Record(context.Background(), approved(claims))
	if err != nil {
		t.Fatal(err)
	}
	claims["tier"] = "mutated after the fact" // the stored approval must not alias the caller's map

	a, err := s.ConsumeApproval(context.Background(), res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != "u" || a.CredentialType != testType || a.Claims["tier"] != "gold" {
		t.Fatalf("approval = %+v", a)
	}
}
