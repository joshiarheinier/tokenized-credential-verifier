// Package challengestore keeps challenges in memory. They are lost
// on restart and not shared between processes, so it suits one backend instance
// (development, the demo); a shared store would replace it for a multi-instance
// deployment. It implements application/challenge.Store.
package challengestore

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
)

// retention is how long a challenge's record, and with it its verdict, outlives
// the challenge's expiry before being forgotten.
const retention = 5 * time.Minute

// Memory is an in-memory challenge store. The zero value is not usable;
// create it with NewMemory.
type Memory struct {
	mu       sync.Mutex
	sessions map[string]*challenge.Session
	max      int
	now      func() time.Time
}

// Option customizes a Memory store.
type Option func(*Memory)

// WithClock overrides the wall clock used to forget old records.
func WithClock(now func() time.Time) Option { return func(m *Memory) { m.now = now } }

// NewMemory returns a store that refuses new challenges while max records are
// held, after forgetting the ones past their retention.
func NewMemory(max int, opts ...Option) *Memory {
	m := &Memory{sessions: make(map[string]*challenge.Session), max: max, now: time.Now}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Create stores a new session, or returns challenge.ErrStoreFull.
func (m *Memory) Create(_ context.Context, s challenge.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= m.max {
		m.forgetOld()
		if len(m.sessions) >= m.max {
			return challenge.ErrStoreFull
		}
	}
	cp := clone(s)
	m.sessions[s.Challenge.ID] = &cp
	return nil
}

// Get returns a copy of the session, or challenge.ErrNotFound.
func (m *Memory) Get(_ context.Context, id string) (challenge.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.live(id)
	if s == nil {
		return challenge.Session{}, challenge.ErrNotFound
	}
	return clone(*s), nil
}

// Consume marks the challenge used and returns it. Of concurrent calls for one
// challenge exactly one succeeds; the others get challenge.ErrAlreadyUsed.
func (m *Memory) Consume(_ context.Context, id string, now time.Time) (challenge.Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.live(id)
	switch {
	case s == nil:
		return challenge.Challenge{}, challenge.ErrNotFound
	case s.Used:
		return challenge.Challenge{}, challenge.ErrAlreadyUsed
	case !now.Before(s.Challenge.ExpiresAt):
		return challenge.Challenge{}, challenge.ErrExpired
	}
	s.Used = true
	return clone(*s).Challenge, nil
}

// Complete records the verdict of a consumed challenge.
func (m *Memory) Complete(_ context.Context, id string, v challenge.Verdict) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.live(id)
	if s == nil {
		return challenge.ErrNotFound
	}
	cp := v
	s.Verdict = &cp
	return nil
}

// live returns the session unless it is unknown or past its retention. Callers
// hold the lock.
func (m *Memory) live(id string) *challenge.Session {
	s := m.sessions[id]
	if s == nil {
		return nil
	}
	if m.now().After(s.Challenge.ExpiresAt.Add(retention)) {
		delete(m.sessions, id)
		return nil
	}
	return s
}

func (m *Memory) forgetOld() {
	now := m.now()
	for id, s := range m.sessions {
		if now.After(s.Challenge.ExpiresAt.Add(retention)) {
			delete(m.sessions, id)
		}
	}
}

func clone(s challenge.Session) challenge.Session {
	s.Challenge.Claims = slices.Clone(s.Challenge.Claims)
	if s.Verdict != nil {
		v := *s.Verdict
		s.Verdict = &v
	}
	return s
}
