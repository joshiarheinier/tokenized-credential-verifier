// Package httpapi exposes the backend over HTTP: routing, middleware and
// handlers. It is named httpapi rather than http to avoid shadowing net/http.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// NewRouter returns the root handler with all routes and middleware applied.
func NewRouter(logger *slog.Logger, api API, checks ...ReadinessCheck) http.Handler {
	mux := http.NewServeMux()

	v1 := &v1Handlers{logger: logger, api: api}

	// Every endpoint is listed here. Routes whose backing service is nil are
	// not registered and respond 404, e.g. simulation and issuance in production.

	// Operational
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("GET /readyz", readyzHandler(logger, checks))

	// Simulated KYC and issuance (development only)
	if api.KYCSimulation != nil {
		mux.HandleFunc("POST /v1/kyc/simulate", v1.simulate)
	}
	if api.CredentialIssuance != nil {
		mux.HandleFunc("POST /v1/credentials", v1.issue)
	}

	// Verification
	if api.CredentialVerification != nil {
		mux.HandleFunc("POST /v1/credentials/verify", v1.verify)
	}

	return recoverPanics(logger, logRequests(logger, mux))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
