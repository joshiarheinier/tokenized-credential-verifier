package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// The challenge-response protocol (docs/challenge_response_protocol.md) as seen
// by a relying application: pose a challenge, send the user to their wallet, then
// read the verdict from the verifier. The application never sees the credential
// or the holder's signature, only the claims it asked for.

// challenge is a challenge the verifier opened for us. Secret lets only us read
// the verdict; it never goes near the browser.
type challenge struct {
	ID     string
	Secret string
}

// challengeResult is the verdict for a challenge.
type challengeResult struct {
	Status string         `json:"status"` // pending, verified, rejected, unavailable, expired
	Reason string         `json:"reason"`
	Issuer string         `json:"issuer"`
	Claims map[string]any `json:"claims"`
}

var errUnknownChallenge = errors.New("the verifier does not know this challenge")

// call sends one request to the verifier and decodes a JSON reply into out. It
// returns the HTTP status; an error means no usable reply was obtained.
func (v verifier) call(ctx context.Context, method, path, bearer string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, v.baseURL+path, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("verifier unreachable: %w", err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("verifier replied %d with an unreadable body", resp.StatusCode)
		}
	}
	return resp.StatusCode, nil
}

// createChallenge asks the verifier to open a challenge for the given claims.
func (v verifier) createChallenge(ctx context.Context, audience, credentialType string, claims []string, callbackURL string) (challenge, error) {
	var out struct {
		ChallengeID  string `json:"challenge_id"`
		ResultSecret string `json:"result_secret"`
	}
	status, err := v.call(ctx, http.MethodPost, "/v1/challenges", "", map[string]any{
		"audience":        audience,
		"credential_type": credentialType,
		"claims":          claims,
		"callback_url":    callbackURL,
	}, &out)
	if err != nil {
		return challenge{}, err
	}
	if status != http.StatusCreated || out.ChallengeID == "" || out.ResultSecret == "" {
		return challenge{}, fmt.Errorf("verifier would not open a challenge (HTTP %d)", status)
	}
	return challenge{ID: out.ChallengeID, Secret: out.ResultSecret}, nil
}

// result reads the verdict for a challenge we created.
func (v verifier) result(ctx context.Context, c challenge) (challengeResult, error) {
	var out challengeResult
	status, err := v.call(ctx, http.MethodGet, "/v1/challenges/"+url.PathEscape(c.ID)+"/result", c.Secret, nil, &out)
	switch {
	case status == http.StatusNotFound:
		return challengeResult{}, errUnknownChallenge
	case err != nil:
		return challengeResult{}, err
	case status != http.StatusOK:
		return challengeResult{}, fmt.Errorf("verifier replied %d", status)
	}
	return out, nil
}
