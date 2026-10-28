package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/joshia/tokenized-identity-kyc/internal/credential"
	"github.com/joshia/tokenized-identity-kyc/internal/identity"
	"github.com/joshia/tokenized-identity-kyc/internal/verification"
)

const maxBodyBytes = 16 * 1024

// KYCSimulationService records simulated KYC decisions. Development only.
type KYCSimulationService interface {
	Simulate(ctx context.Context, req identity.SimulationRequest) (identity.Result, error)
}

// CredentialIssuanceService issues credentials for approved KYC results.
type CredentialIssuanceService interface {
	IssueFromApproval(ctx context.Context, approvalID string) (credential.Issued, error)
}

// CredentialVerificationService verifies presented credentials.
type CredentialVerificationService interface {
	Verify(ctx context.Context, token string) verification.Result
}

// API holds the services behind the /v1 routes. A nil field leaves its routes
// unregistered (they return 404), e.g. simulation and issuance in production.
type API struct {
	KYCSimulation          KYCSimulationService
	CredentialIssuance     CredentialIssuanceService
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
	Subject string           `json:"subject"`
	Outcome identity.Outcome `json:"outcome"`
	Over18  bool             `json:"over_18"`
	Country string           `json:"country"`
}

type simulateResponse struct {
	KYCResultID string           `json:"kyc_result_id"`
	Outcome     identity.Outcome `json:"outcome"`
}

func (h *v1Handlers) simulate(w http.ResponseWriter, r *http.Request) {
	var req simulateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	res, err := h.api.KYCSimulation.Simulate(r.Context(), identity.SimulationRequest{
		Subject: req.Subject, Outcome: req.Outcome, Over18: req.Over18, Country: req.Country,
	})
	if err != nil {
		if errors.Is(err, identity.ErrInvalidRequest) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, simulateResponse{KYCResultID: res.ID, Outcome: res.Outcome})
}

type issueRequest struct {
	KYCResultID string `json:"kyc_result_id"`
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
	if req.KYCResultID == "" {
		writeError(w, http.StatusBadRequest, "kyc_result_id is required")
		return
	}
	issued, err := h.api.CredentialIssuance.IssueFromApproval(r.Context(), req.KYCResultID)
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, issueResponse{Credential: issued.Token, ExpiresAt: issued.ExpiresAt})
	case errors.Is(err, identity.ErrNotFound):
		writeError(w, http.StatusNotFound, "kyc result not found")
	case errors.Is(err, identity.ErrNotApproved):
		writeError(w, http.StatusUnprocessableEntity, "kyc result was not approved")
	case errors.Is(err, identity.ErrAlreadyUsed):
		writeError(w, http.StatusConflict, "a credential was already issued for this kyc result")
	default:
		h.internalError(w, r, err)
	}
}

type verifyRequest struct {
	Credential string `json:"credential"`
}

type verifyResponse struct {
	Valid          bool                  `json:"valid"`
	Reason         verification.Reason   `json:"reason,omitempty"`
	Issuer         string                `json:"issuer,omitempty"`
	CredentialType string                `json:"credential_type,omitempty"`
	ExpiresAt      *time.Time            `json:"expires_at,omitempty"`
	Claims         *credential.KYCClaims `json:"claims,omitempty"`
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
		Claims:         &res.Claims,
	})
}

func (h *v1Handlers) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}
