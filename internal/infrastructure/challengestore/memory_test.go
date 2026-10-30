package challengestore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
)

var (
	t0  = time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	ctx = context.Background()
)

func session(t *testing.T, id string) challenge.Session {
	t.Helper()
	c, err := challenge.NewChallenge(id, "http://localhost:9090", "KYCStatus", []string{"over_18"}, "", t0.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return challenge.Session{Challenge: c}
}

func TestConsumeIsAtomicAcrossConcurrentCalls(t *testing.T) {
	m := NewMemory(10)
	if err := m.Create(ctx, session(t, "c1")); err != nil {
		t.Fatal(err)
	}

	var won, used atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch _, err := m.Consume(ctx, "c1", t0); {
			case err == nil:
				won.Add(1)
			case errors.Is(err, challenge.ErrAlreadyUsed):
				used.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 || used.Load() != 49 {
		t.Fatalf("won=%d alreadyUsed=%d, want exactly one winner among 50", won.Load(), used.Load())
	}
}

func TestConsumeRefusesUnknownAndExpired(t *testing.T) {
	m := NewMemory(10)
	if err := m.Create(ctx, session(t, "c1")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(ctx, "nope", t0); !errors.Is(err, challenge.ErrNotFound) {
		t.Errorf("unknown: err = %v, want ErrNotFound", err)
	}
	if _, err := m.Consume(ctx, "c1", t0.Add(5*time.Minute)); !errors.Is(err, challenge.ErrExpired) {
		t.Errorf("at expiry: err = %v, want ErrExpired", err)
	}
	// An expired challenge was never spent, so a late attempt does not use it up.
	if _, err := m.Consume(ctx, "c1", t0); err != nil {
		t.Errorf("an unexpired attempt after a late one: %v", err)
	}
}

func TestVerdictIsKeptThenForgotten(t *testing.T) {
	now := t0
	m := NewMemory(10, WithClock(func() time.Time { return now }))
	if err := m.Create(ctx, session(t, "c1")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(ctx, "c1", t0); err != nil {
		t.Fatal(err)
	}
	if err := m.Complete(ctx, "c1", challenge.Verdict{Status: challenge.StatusVerified}); err != nil {
		t.Fatal(err)
	}

	now = t0.Add(9 * time.Minute) // past expiry, inside retention
	if s, err := m.Get(ctx, "c1"); err != nil || s.Verdict == nil || s.Verdict.Status != challenge.StatusVerified {
		t.Fatalf("Get = %+v, %v, want the verdict still readable", s, err)
	}
	now = t0.Add(11 * time.Minute) // past retention
	if _, err := m.Get(ctx, "c1"); !errors.Is(err, challenge.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound after retention", err)
	}
}

func TestStoreIsCappedButMakesRoomByForgettingOldRecords(t *testing.T) {
	now := t0
	m := NewMemory(2, WithClock(func() time.Time { return now }))
	for _, id := range []string{"a", "b"} {
		if err := m.Create(ctx, session(t, id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Create(ctx, session(t, "c")); !errors.Is(err, challenge.ErrStoreFull) {
		t.Fatalf("err = %v, want ErrStoreFull while two are open", err)
	}

	now = t0.Add(11 * time.Minute) // both are past retention
	if err := m.Create(ctx, session(t, "c")); err != nil {
		t.Fatalf("after old records expired: %v", err)
	}
}

func TestStoredSessionsAreCopies(t *testing.T) {
	m := NewMemory(10)
	s := session(t, "c1")
	if err := m.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Challenge.Claims[0] = "tampered"

	got, _ := m.Get(ctx, "c1")
	if got.Challenge.Claims[0] != "over_18" {
		t.Fatal("changing the caller's session changed the stored one")
	}
	got.Challenge.Claims[0] = "tampered"
	again, _ := m.Get(ctx, "c1")
	if again.Challenge.Claims[0] != "over_18" {
		t.Fatal("changing a returned session changed the stored one")
	}
}
