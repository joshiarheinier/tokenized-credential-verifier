// Package httpapi exposes the backend over HTTP: routing, middleware and
// handlers. It is named httpapi rather than http to avoid shadowing net/http.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// NewRouter returns the root handler with all routes and middleware applied.
func NewRouter(logger *slog.Logger, checks ...ReadinessCheck) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("GET /readyz", readyzHandler(logger, checks))

	return recoverPanics(logger, logRequests(logger, mux))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
