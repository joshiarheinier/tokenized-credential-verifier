package http

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

const readinessTimeout = 2 * time.Second

// ReadinessCheck reports whether a dependency the API needs (database,
// Solana RPC, ...) is usable. Check must respect ctx cancellation.
type ReadinessCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

type statusResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

// handleHealthz reports process liveness only; it never touches dependencies.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

// readyzHandler reports whether every readiness check passes. Failure details
// are logged but not returned, so internal errors are not exposed to callers.
func readyzHandler(logger *slog.Logger, checks []ReadinessCheck) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()

		resp := statusResponse{Status: "ready", Checks: make(map[string]string, len(checks))}
		status := http.StatusOK
		for _, c := range checks {
			if err := c.Check(ctx); err != nil {
				logger.WarnContext(ctx, "readiness check failed", "check", c.Name, "error", err)
				resp.Checks[c.Name] = "fail"
				resp.Status = "not_ready"
				status = http.StatusServiceUnavailable
				continue
			}
			resp.Checks[c.Name] = "ok"
		}
		writeJSON(w, status, resp)
	})
}
