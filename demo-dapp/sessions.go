package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// session is what the application remembers about one browser: the challenge it
// started and, once the verifier says so, what it learned. It is kept in memory
// and found by a random cookie, so a challenge id seen in a URL is not enough to
// read anyone's result.
type session struct {
	Challenge challenge
	Verified  bool
	Claims    map[string]any
	expires   time.Time
}

type sessions struct {
	mu  sync.Mutex
	m   map[string]*session
	max int
	ttl time.Duration
	now func() time.Time
}

func newSessions(max int, ttl time.Duration) *sessions {
	return &sessions{m: make(map[string]*session), max: max, ttl: ttl, now: time.Now}
}

var errTooManySessions = errors.New("too many open sessions")

// create starts a session for a challenge and returns its id.
func (s *sessions) create(c challenge) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= s.max {
		for k, v := range s.m {
			if !s.now().Before(v.expires) {
				delete(s.m, k)
			}
		}
		if len(s.m) >= s.max {
			return "", errTooManySessions
		}
	}
	s.m[id] = &session{Challenge: c, expires: s.now().Add(s.ttl)}
	return id, nil
}

// get returns a copy of the session, if there is a live one.
func (s *sessions) get(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok || !s.now().Before(sess.expires) {
		delete(s.m, id)
		return session{}, false
	}
	return *sess, true
}

// markVerified records what the verifier told us for the session's challenge.
func (s *sessions) markVerified(id string, claims map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[id]; ok {
		sess.Verified = true
		sess.Claims = claims
	}
}

func (s *sessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}
