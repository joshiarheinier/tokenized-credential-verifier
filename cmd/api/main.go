// Command api runs the credential verifier backend HTTP server.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/app"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, cfg.Log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	if err := a.Run(ctx); err != nil {
		logger.Error("api exited with error", "error", err)
		return err
	}
	return nil
}
