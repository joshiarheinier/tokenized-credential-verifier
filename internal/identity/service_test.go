package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConsumeApprovalOnlyOnceUnderConcurrency(t *testing.T) {
	s := NewService()
	res, err := s.Simulate(context.Background(), SimulationRequest{Subject: "u", Outcome: OutcomeApproved, Country: "ID"})
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
	s := NewService()
	res, _ := s.Simulate(context.Background(), SimulationRequest{Subject: "u", Outcome: OutcomeRejected})
	if _, err := s.ConsumeApproval(context.Background(), res.ID); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err = %v, want ErrNotApproved", err)
	}
}
