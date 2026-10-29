// Package http is the HTTP gateway: how the outside world reaches the
// application. It holds routing, middleware and handlers, translates requests
// into calls on the application services (approval, credential issuance,
// verification) and their results into responses. It contains no business
// rules of its own.
//
// The package is named after its directory (internal/gateways/http) and
// therefore has the same name as net/http, which it imports under the usual
// name. Importers that also use net/http should alias this package, for
// example as httpgateway.
package http

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

	// Simulated approvals and issuance (development only)
	if api.ApprovalSimulation != nil {
		mux.HandleFunc("POST /v1/approvals/simulate", v1.simulate)
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
