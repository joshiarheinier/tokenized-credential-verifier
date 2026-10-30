// Command demo-dapp is a demonstration relying application: a service with one
// gated resource that lets a user in if they present a valid KYC credential.
//
// It is deliberately a separate program from the credential verifier backend. It
// holds no keys and does no cryptography; it asks the verifier's HTTP API
// (POST /v1/credentials/verify) whether the presented credential is acceptable
// and obeys the answer. Anything other than a clear "valid" is a denial, so an
// unreachable or misbehaving verifier never grants access.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	maxBodyBytes      = 16 * 1024
	verifierTimeout   = 10 * time.Second
	reasonUnavailable = "verification_unavailable"
)

// verifier calls the credential verifier's HTTP API.
type verifier struct {
	baseURL string
	client  *http.Client
}

type verifyResult struct {
	Valid          bool           `json:"valid"`
	Reason         string         `json:"reason"`
	Issuer         string         `json:"issuer"`
	CredentialType string         `json:"credential_type"`
	Claims         map[string]any `json:"claims"`
}

// verify returns the verifier's verdict. An error means no verdict could be
// obtained; callers must treat it as a denial.
func (v verifier) verify(ctx context.Context, credential string) (verifyResult, error) {
	body, _ := json.Marshal(map[string]string{"credential": credential})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+"/v1/credentials/verify", bytes.NewReader(body))
	if err != nil {
		return verifyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return verifyResult{}, fmt.Errorf("verifier unreachable: %w", err)
	}
	defer resp.Body.Close()

	// Only a 200 carries a verdict: a 503 means the verifier could not establish
	// trust state, and anything else is not a reply this app understands.
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		return verifyResult{}, errors.New("verifier could not establish trust state")
	case resp.StatusCode != http.StatusOK:
		return verifyResult{}, fmt.Errorf("verifier replied %d", resp.StatusCode)
	}
	var res verifyResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&res); err != nil {
		return verifyResult{}, errors.New("verifier replied with an unreadable body")
	}
	return res, nil
}

// app is the demo application.
type app struct {
	verifier verifier
	log      func(format string, args ...any)
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /access", a.access)
	return mux
}

type accessRequest struct {
	Credential string `json:"credential"`
}

type accessResponse struct {
	Access  string         `json:"access"` // "granted" or "denied"
	Reason  string         `json:"reason,omitempty"`
	Message string         `json:"message,omitempty"`
	Issuer  string         `json:"issuer,omitempty"`
	Claims  map[string]any `json:"claims,omitempty"`
}

func (a *app) access(w http.ResponseWriter, r *http.Request) {
	var req accessRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Credential == "" {
		reply(w, http.StatusBadRequest, accessResponse{Access: "denied", Reason: "a credential is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), verifierTimeout)
	defer cancel()
	status, resp := a.decide(ctx, req.Credential)
	reply(w, status, resp)
}

// decide asks the verifier about a presented credential and turns the answer
// into the app's access decision and HTTP status.
func (a *app) decide(ctx context.Context, credential string) (int, accessResponse) {
	res, err := a.verifier.verify(ctx, credential)
	switch {
	case err != nil:
		a.log("access denied: %v", err)
		return http.StatusServiceUnavailable, accessResponse{Access: "denied", Reason: reasonUnavailable}
	case !res.Valid:
		a.log("access denied: %s", res.Reason)
		return http.StatusForbidden, accessResponse{Access: "denied", Reason: res.Reason}
	}
	a.log("access granted: issuer=%s type=%s", res.Issuer, res.CredentialType)
	return http.StatusOK, accessResponse{
		Access:  "granted",
		Message: "welcome: this is the members-only area",
		Issuer:  res.Issuer,
		Claims:  res.Claims,
	}
}

func reply(w http.ResponseWriter, status int, body accessResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
