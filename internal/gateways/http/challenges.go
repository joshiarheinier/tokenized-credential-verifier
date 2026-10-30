package http

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/challenge"
	domainchallenge "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/challenge"
)

// ChallengeService runs the challenge-response protocol
// (docs/challenge_response_protocol.md): challenges created by relying
// applications, responses submitted by wallets, and verdicts read back by the
// creators.
// application/challenge.Service implements it.
type ChallengeService interface {
	CreateChallenge(ctx context.Context, req challenge.CreateRequest) (challenge.Created, error)
	GetChallenge(ctx context.Context, id string) (challenge.View, error)
	RespondChallenge(ctx context.Context, id, token string, holderSignature []byte) (domainchallenge.Verdict, error)
	GetChallengeResult(ctx context.Context, id, secret string) (domainchallenge.Verdict, error)
}

type createChallengeRequest struct {
	Audience       string   `json:"audience"`
	CredentialType string   `json:"credential_type"`
	Claims         []string `json:"claims"`
	CallbackURL    string   `json:"callback_url"`
}

type challengeResponse struct {
	ChallengeID    string    `json:"challenge_id"`
	Status         string    `json:"status,omitempty"`
	Audience       string    `json:"audience"`
	CredentialType string    `json:"credential_type"`
	Claims         []string  `json:"claims"`
	CallbackURL    string    `json:"callback_url,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type createdChallengeResponse struct {
	challengeResponse
	ResultSecret string `json:"result_secret"`
}

func newChallengeResponse(c domainchallenge.Challenge) challengeResponse {
	return challengeResponse{
		ChallengeID:    c.ID,
		Audience:       c.Audience,
		CredentialType: c.CredentialType,
		Claims:         c.Claims,
		CallbackURL:    c.CallbackURL,
		ExpiresAt:      c.ExpiresAt,
	}
}

func (h *v1Handlers) createChallenge(w http.ResponseWriter, r *http.Request) {
	var req createChallengeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	created, err := h.api.Challenges.CreateChallenge(r.Context(), challenge.CreateRequest{
		Audience:       req.Audience,
		CredentialType: req.CredentialType,
		Claims:         req.Claims,
		CallbackURL:    req.CallbackURL,
	})
	if err != nil {
		h.challengeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdChallengeResponse{
		challengeResponse: newChallengeResponse(created.Challenge),
		ResultSecret:      created.ResultSecret,
	})
}

func (h *v1Handlers) getChallenge(w http.ResponseWriter, r *http.Request) {
	view, err := h.api.Challenges.GetChallenge(r.Context(), r.PathValue("id"))
	if err != nil {
		h.challengeError(w, r, err)
		return
	}
	resp := newChallengeResponse(view.Challenge)
	resp.Status = "pending"
	if view.Completed {
		resp.Status = "completed"
	}
	writeJSON(w, http.StatusOK, resp)
}

type respondChallengeRequest struct {
	Credential      string `json:"credential"`
	HolderSignature string `json:"holder_signature"`
}

type respondChallengeResponse struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func (h *v1Handlers) respondChallenge(w http.ResponseWriter, r *http.Request) {
	var req respondChallengeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	signature, err := base64.StdEncoding.DecodeString(req.HolderSignature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "holder_signature must be standard base64")
		return
	}
	verdict, err := h.api.Challenges.RespondChallenge(r.Context(), r.PathValue("id"), req.Credential, signature)
	if err != nil {
		h.challengeError(w, r, err)
		return
	}
	// The wallet learns the outcome, never the claims: only the creator of the
	// challenge may read those.
	status := http.StatusOK
	if verdict.Status == domainchallenge.StatusUnavailable {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, respondChallengeResponse{Status: string(verdict.Status), Reason: verdict.Reason})
}

type resultResponse struct {
	Status              string         `json:"status"`
	Reason              string         `json:"reason,omitempty"`
	Issuer              string         `json:"issuer,omitempty"`
	CredentialType      string         `json:"credential_type,omitempty"`
	Claims              map[string]any `json:"claims,omitempty"`
	CredentialExpiresAt *time.Time     `json:"credential_expires_at,omitempty"`
}

func (h *v1Handlers) challengeResult(w http.ResponseWriter, r *http.Request) {
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || secret == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "the result secret is required as a bearer token")
		return
	}
	verdict, err := h.api.Challenges.GetChallengeResult(r.Context(), r.PathValue("id"), secret)
	if err != nil {
		h.challengeError(w, r, err)
		return
	}
	resp := resultResponse{Status: string(verdict.Status), Reason: verdict.Reason}
	if verdict.Status == domainchallenge.StatusVerified {
		resp.Issuer = verdict.Issuer
		resp.CredentialType = verdict.CredentialType
		resp.Claims = verdict.Claims
		resp.CredentialExpiresAt = &verdict.CredentialExpiresAt
	}
	writeJSON(w, http.StatusOK, resp)
}

// challengeError maps the challenge errors to statuses.
func (h *v1Handlers) challengeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domainchallenge.ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, domainchallenge.ErrNotFound):
		writeError(w, http.StatusNotFound, "challenge not found")
	case errors.Is(err, domainchallenge.ErrExpired):
		writeError(w, http.StatusGone, "challenge expired")
	case errors.Is(err, domainchallenge.ErrAlreadyUsed):
		writeError(w, http.StatusConflict, "challenge already used")
	case errors.Is(err, domainchallenge.ErrStoreFull):
		writeError(w, http.StatusServiceUnavailable, "too many open challenges, try again later")
	default:
		h.internalError(w, r, err)
	}
}
