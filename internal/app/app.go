// Package app wires configuration, dependencies and the HTTP server together
// and owns the process lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/joshia/tokenized-identity-kyc/internal/config"
	"github.com/joshia/tokenized-identity-kyc/internal/credential"
	"github.com/joshia/tokenized-identity-kyc/internal/httpapi"
	"github.com/joshia/tokenized-identity-kyc/internal/identity"
	"github.com/joshia/tokenized-identity-kyc/internal/issuer"
	"github.com/joshia/tokenized-identity-kyc/internal/verification"
)

// App is the assembled API application.
type App struct {
	cfg    config.Config
	logger *slog.Logger
	server *http.Server
}

// New assembles the application from its configuration.
func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	api, err := buildAPI(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &App{
		cfg:    cfg,
		logger: logger,
		server: &http.Server{
			Handler:           httpapi.NewRouter(logger, api),
			ReadTimeout:       cfg.HTTP.ReadTimeout,
			ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
			WriteTimeout:      cfg.HTTP.WriteTimeout,
			IdleTimeout:       cfg.HTTP.IdleTimeout,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
	}, nil
}

func buildAPI(cfg config.Config, logger *slog.Logger) (httpapi.API, error) {
	seed := cfg.Issuer.SigningKeySeed
	if seed == "" {
		// config.Load guarantees this only happens outside production.
		var err error
		if seed, err = issuer.GenerateSeed(); err != nil {
			return httpapi.API{}, err
		}
		logger.Warn("ISSUER_SIGNING_KEY_SEED not set: using an ephemeral issuer key; issued credentials will not verify after restart")
	}
	iss, err := issuer.New(cfg.Issuer.ID, seed)
	if err != nil {
		return httpapi.API{}, fmt.Errorf("issuer: %w", err)
	}

	verifier := credential.NewVerifier(nil)
	verifier.Trust(iss.ID, iss.Signer.PublicKey())
	api := httpapi.API{CredentialVerification: verification.NewService(verifier, verification.DefaultPolicy)}

	if cfg.KYC.SimulationEnabled {
		logger.Warn("simulated KYC is enabled: for local development only")
		kyc := identity.NewService()
		issuing, err := credential.NewService(iss.Signer, kyc, cfg.Issuer.CredentialTTL, nil)
		if err != nil {
			return httpapi.API{}, err
		}
		api.KYCSimulation = kyc
		api.CredentialIssuance = issuing
	}
	return api, nil
}

// Run listens on the configured address and serves until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", a.cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", a.cfg.HTTP.Addr, err)
	}
	return a.Serve(ctx, ln)
}

// Serve serves HTTP on ln until ctx is cancelled, then shuts down gracefully,
// giving in-flight requests up to the configured shutdown timeout to finish.
func (a *App) Serve(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		a.logger.Info("http server listening", "addr", ln.Addr().String(), "env", a.cfg.Env)
		errCh <- a.server.Serve(ln)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	a.logger.Info("shutting down http server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http server shutdown: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	a.logger.Info("http server stopped")
	return nil
}
