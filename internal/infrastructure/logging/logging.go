// Package logging constructs the process-wide structured logger.
package logging

import (
	"io"
	"log/slog"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
)

// New returns a slog.Logger writing to w in the configured format and level.
func New(w io.Writer, cfg config.LogConfig) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.Level}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
