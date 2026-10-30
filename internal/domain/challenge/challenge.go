// Package challenge is the domain model of the challenge-response protocol
// (docs/challenge_response_protocol.md): the challenge a relying application
// creates, the text a holder signs to consent, and the check that binds a
// credential to the key of its holder. In the wider credential ecosystem the
// holder's response is called a presentation. It has no dependencies on the rest of the
// project.
package challenge

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"time"
)

var (
	// ErrInvalidRequest means a challenge request or a response is not well
	// formed.
	ErrInvalidRequest = errors.New("challenge: invalid request")
	// ErrNotFound means no such challenge exists (or it is long gone).
	ErrNotFound = errors.New("challenge: not found")
	// ErrExpired means the challenge's lifetime is over.
	ErrExpired = errors.New("challenge: expired")
	// ErrAlreadyUsed means a response was already attempted against the
	// challenge.
	ErrAlreadyUsed = errors.New("challenge: already used")
	// ErrStoreFull means too many challenges are open.
	ErrStoreFull = errors.New("challenge: too many open challenges")
)

const maxClaims = 16

var (
	claimRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	typeRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

// Challenge is a relying application's request for a response, valid until
// ExpiresAt and usable once.
type Challenge struct {
	// ID is public and doubles as the nonce in the signed message.
	ID string
	// Audience is the origin of the relying application.
	Audience       string
	CredentialType string
	// Claims are the claims wanted: sorted, distinct.
	Claims []string
	// CallbackURL is where the wallet sends the user afterwards; empty if none.
	// It has the same origin as Audience.
	CallbackURL string
	ExpiresAt   time.Time
}

// NewChallenge validates a challenge request and returns it normalized: the
// claims are sorted and the expiry is in UTC. id must be unguessable.
func NewChallenge(id, audience, credentialType string, claims []string, callbackURL string, expiresAt time.Time) (Challenge, error) {
	if id == "" {
		return Challenge{}, fmt.Errorf("%w: missing id", ErrInvalidRequest)
	}
	if err := checkOrigin(audience); err != nil {
		return Challenge{}, fmt.Errorf("%w: audience: %v", ErrInvalidRequest, err)
	}
	if !typeRE.MatchString(credentialType) {
		return Challenge{}, fmt.Errorf("%w: credential_type is not valid", ErrInvalidRequest)
	}
	if len(claims) == 0 || len(claims) > maxClaims {
		return Challenge{}, fmt.Errorf("%w: claims must list 1 to %d claims", ErrInvalidRequest, maxClaims)
	}
	sorted := slices.Clone(claims)
	slices.Sort(sorted)
	for i, c := range sorted {
		if !claimRE.MatchString(c) {
			return Challenge{}, fmt.Errorf("%w: claim name %q is not valid", ErrInvalidRequest, c)
		}
		if i > 0 && sorted[i-1] == c {
			return Challenge{}, fmt.Errorf("%w: claim %q is listed twice", ErrInvalidRequest, c)
		}
	}
	if callbackURL != "" {
		if err := checkCallback(callbackURL, audience); err != nil {
			return Challenge{}, fmt.Errorf("%w: callback_url: %v", ErrInvalidRequest, err)
		}
	}
	return Challenge{
		ID:             id,
		Audience:       audience,
		CredentialType: credentialType,
		Claims:         sorted,
		CallbackURL:    callbackURL,
		ExpiresAt:      expiresAt.UTC(),
	}, nil
}

// checkOrigin accepts scheme://host[:port] with nothing else, over https, or
// over http for local development hosts. The text ends up in a message shown to
// the user, so it must be plain ASCII.
func checkOrigin(s string) error {
	u, err := parseASCII(s)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("must be an origin: scheme://host[:port]")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"):
	default:
		return errors.New("must use https (http only for localhost)")
	}
	return nil
}

func checkCallback(callback, audience string) error {
	u, err := parseASCII(callback)
	if err != nil {
		return err
	}
	if u.Fragment != "" || u.User != nil {
		return errors.New("must not contain credentials or a fragment")
	}
	if got := u.Scheme + "://" + u.Host; got != audience {
		return errors.New("must have the same origin as the audience")
	}
	return nil
}

func parseASCII(s string) (*url.URL, error) {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return nil, errors.New("must be printable ASCII without spaces")
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("is not a valid URL")
	}
	return u, nil
}

// Status is where a challenge stands.
type Status string

const (
	StatusPending     Status = "pending"
	StatusVerified    Status = "verified"
	StatusRejected    Status = "rejected"
	StatusUnavailable Status = "unavailable"
	StatusExpired     Status = "expired"
)

// Verdict is the outcome of answering a challenge.
type Verdict struct {
	Status Status
	// Reason is a coarse code for a rejection or unavailability.
	Reason string
	// The rest is set only for StatusVerified. Claims holds exactly the claims
	// the challenge asked for.
	Issuer              string
	CredentialType      string
	Claims              map[string]any
	CredentialExpiresAt time.Time
}

// Session is a challenge together with its state. SecretHash is the SHA-256 of
// the result secret, which is never stored.
type Session struct {
	Challenge  Challenge
	SecretHash [32]byte
	Used       bool
	Verdict    *Verdict
}
