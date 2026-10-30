package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/approval"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/verification"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
)

const maxBodyBytes = 16 * 1024

// ApprovalSimulationService backs the dev-only endpoint that lets a caller
// declare an issuer approval without any real check. It records the decision
// through the approval package.
type ApprovalSimulationService interface {
	Record(ctx context.Context, req approval.Request) (approval.Result, error)
}

// CredentialService is the issuing side of the credential lifecycle: issuing
// credentials for approvals, revoking them, and suspending or reactivating this
// deployment's issuer in the registry. application/credential.Service
// implements it.
type CredentialService interface {
	IssueFromApproval(ctx context.Context, approvalID string) (credential.Issued, error)
	Revoke(ctx context.Context, token string) error
	SetIssuerActive(ctx context.Context, active bool) error
}

// CredentialVerificationService verifies presented credentials.
type CredentialVerificationService interface {
	Verify(ctx context.Context, token string) verification.Result
}

// API holds the services behind the /v1 routes. A nil field leaves its routes
// unregistered (they return 404), e.g. simulation and issuance in production.
type API struct {
	ApprovalSimulation     ApprovalSimulationService
	Credentials            CredentialService
	CredentialVerification CredentialVerificationService
}

// v1Handlers holds the /v1 handler methods. Routes are bound to them in
// NewRouter (router.go), the single place where every endpoint is listed.
type v1Handlers struct {
	logger *slog.Logger
	api    API
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

// decodeBody reads a single JSON object, rejecting unknown fields, oversized
// bodies and trailing data.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid JSON request body")
		}
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "unexpected data after JSON body")
		return false
	}
	return true
}

type simulateRequest struct {
	Subject        string           `json:"subject"`
	CredentialType string           `json:"credential_type"`
	Outcome        approval.Outcome `json:"outcome"`
	Claims         map[string]any   `json:"claims"`
}

type simulateResponse struct {
	ApprovalID string           `json:"approval_id"`
	Outcome    approval.Outcome `json:"outcome"`
}

func (h *v1Handlers) simulate(w http.ResponseWriter, r *http.Request) {
	var req simulateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	res, err := h.api.ApprovalSimulation.Record(r.Context(), approval.Request{
		Subject: req.Subject, CredentialType: req.CredentialType, Outcome: req.Outcome, Claims: req.Claims,
	})
	if err != nil {
		if errors.Is(err, approval.ErrInvalidRequest) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, simulateResponse{ApprovalID: res.ID, Outcome: res.Outcome})
}

type issueRequest struct {
	ApprovalID string `json:"approval_id"`
}

type issueResponse struct {
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (h *v1Handlers) issue(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ApprovalID == "" {
		writeError(w, http.StatusBadRequest, "approval_id is required")
		return
	}
	issued, err := h.api.Credentials.IssueFromApproval(r.Context(), req.ApprovalID)
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, issueResponse{Credential: issued.Token, ExpiresAt: issued.ExpiresAt})
	case errors.Is(err, approval.ErrNotFound):
		writeError(w, http.StatusNotFound, "approval not found")
	case errors.Is(err, approval.ErrNotApproved):
		writeError(w, http.StatusUnprocessableEntity, "approval was not approved")
	case errors.Is(err, approval.ErrAlreadyUsed):
		writeError(w, http.StatusConflict, "a credential was already issued for this approval")
	default:
		h.internalError(w, r, err)
	}
}

type revokeRequest struct {
	Credential string `json:"credential"`
}

func (h *v1Handlers) revoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Credential == "" {
		writeError(w, http.StatusBadRequest, "credential is required")
		return
	}
	err := h.api.Credentials.Revoke(r.Context(), req.Credential)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	case errors.Is(err, credential.ErrInvalidCredential):
		writeError(w, http.StatusUnprocessableEntity, "not a valid, unexpired credential issued by this service")
	case errors.Is(err, credential.ErrNoRegistry):
		writeError(w, http.StatusNotImplemented, "revocation requires an on-chain registry")
	case errors.Is(err, registry.ErrNotFound):
		writeError(w, http.StatusNotFound, "credential is not registered on chain")
	case errors.Is(err, registry.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "registry unavailable")
	default:
		h.internalError(w, r, err)
	}
}

func (h *v1Handlers) setIssuerActive(active bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h.api.Credentials.SetIssuerActive(r.Context(), active)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, map[string]bool{"active": active})
		case errors.Is(err, credential.ErrNoRegistry):
			writeError(w, http.StatusNotImplemented, "changing issuer status requires an on-chain registry")
		case errors.Is(err, registry.ErrNotFound):
			writeError(w, http.StatusNotFound, "issuer is not registered on chain")
		case errors.Is(err, registry.ErrUnavailable):
			writeError(w, http.StatusServiceUnavailable, "registry unavailable")
		default:
			h.internalError(w, r, err)
		}
	}
}

type verifyRequest struct {
	Credential string `json:"credential"`
}

type verifyResponse struct {
	Valid          bool                `json:"valid"`
	Reason         verification.Reason `json:"reason,omitempty"`
	Issuer         string              `json:"issuer,omitempty"`
	CredentialType string              `json:"credential_type,omitempty"`
	ExpiresAt      *time.Time          `json:"expires_at,omitempty"`
	Claims         map[string]any      `json:"claims,omitempty"`
}

func (h *v1Handlers) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Credential == "" {
		writeError(w, http.StatusBadRequest, "credential is required")
		return
	}
	res := h.api.CredentialVerification.Verify(r.Context(), req.Credential)
	if !res.Valid {
		status := http.StatusOK
		if res.Reason == verification.ReasonUnavailable {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, verifyResponse{Valid: false, Reason: res.Reason})
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{
		Valid:          true,
		Issuer:         res.Issuer,
		CredentialType: res.CredentialType,
		ExpiresAt:      &res.ExpiresAt,
		Claims:         res.Claims,
	})
}

func (h *v1Handlers) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}
