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
	"time"

	"github.com/joshia/tokenized-credential-verifier/internal/config"
	"github.com/joshia/tokenized-credential-verifier/internal/credential"
	"github.com/joshia/tokenized-credential-verifier/internal/credential/kyc"
	"github.com/joshia/tokenized-credential-verifier/internal/httpapi"
	"github.com/joshia/tokenized-credential-verifier/internal/issuer"
	"github.com/joshia/tokenized-credential-verifier/internal/simulation"
	"github.com/joshia/tokenized-credential-verifier/internal/verification"
	"github.com/joshia/tokenized-credential-verifier/pkg/connector/blockchain"
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

	var (
		chain      *blockchain.Client
		verifyOpts []verification.Option
		issueOpts  []credential.ServiceOption
	)
	if cfg.Solana.RPCURL != "" {
		if chain, err = blockchain.NewClient(blockchain.Config{
			RPCURL:                   cfg.Solana.RPCURL,
			ProgramID:                cfg.Solana.ProgramID,
			Commitment:               cfg.Solana.Commitment,
			RegistryAuthorityKeypair: cfg.Solana.RegistryAuthorityKeypair,
			IssuerAuthorityKeypair:   cfg.Solana.IssuerAuthorityKeypair,
			RequestTimeout:           cfg.Solana.RequestTimeout,
			TxTimeout:                cfg.Solana.TxTimeout,
		}); err != nil {
			return httpapi.API{}, err
		}
		verifyOpts = append(verifyOpts, verification.WithBlockchainClient(chain))
		issueOpts = append(issueOpts, credential.WithBlockchainClient(chain))
		logger.Info("on-chain registry enabled", "rpc_url", cfg.Solana.RPCURL, "program_id", cfg.Solana.ProgramID, "commitment", cfg.Solana.Commitment)
		if cfg.Solana.Bootstrap {
			if err := bootstrapRegistry(chain, iss, cfg.Solana.TxTimeout, logger); err != nil {
				return httpapi.API{}, err
			}
		}
	} else {
		logger.Warn("SOLANA_RPC_URL not set: credentials are verified off-chain only, with no issuer trust or revocation check")
	}

	schemas, policies, err := credentialTypes()
	if err != nil {
		return httpapi.API{}, err
	}
	verifier := credential.NewVerifier(schemas, nil)
	verifier.Trust(iss.ID, iss.Signer.PublicKey())
	api := httpapi.API{CredentialVerification: verification.NewService(verifier, policies, verifyOpts...)}

	if cfg.Simulation.Enabled {
		logger.Warn("simulated approvals are enabled: for local development only")
		approvals := simulation.NewService(schemas)
		issuing, err := credential.NewService(iss.Signer, approvals, schemas, cfg.Issuer.CredentialTTL, nil, issueOpts...)
		if err != nil {
			return httpapi.API{}, err
		}
		api.ApprovalSimulation = approvals
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

// bootstrapRegistry makes sure the registry exists and this process's issuer is
// registered. Every step is idempotent, so it is safe on every start. It is a
// development convenience; config.Load refuses it in production.
func bootstrapRegistry(chain *blockchain.Client, iss *issuer.Issuer, txTimeout time.Duration, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*txTimeout)
	defer cancel()

	if _, err := chain.InitializeRegistry(ctx); err != nil {
		return fmt.Errorf("bootstrap registry: %w", err)
	}
	authority, err := chain.IssuerAuthority()
	if err != nil {
		return fmt.Errorf("bootstrap registry: %w", err)
	}
	res, err := chain.RegisterIssuer(ctx, blockchain.IssuerID(iss.ID), iss.Signer.PublicKey(), authority)
	if err != nil {
		return fmt.Errorf("bootstrap registry: register issuer: %w", err)
	}
	logger.Warn("registry bootstrap enabled: for local development only", "issuer", iss.ID, "issuer_registered_now", res.Changed)
	return nil
}

// credentialTypes declares which credential types this deployment understands
// and what it requires of each. To support another type (a ticket, a membership)
// add its Schema here and a Policy saying which claims this application demands;
// nothing else in the credential, verification or registry code changes. See
// docs/credential_types.md.
func credentialTypes() (*credential.Schemas, []verification.Policy, error) {
	schemas, err := credential.NewSchemas(kyc.Schema)
	if err != nil {
		return nil, nil, fmt.Errorf("credential types: %w", err)
	}
	policies := []verification.Policy{
		{
			CredentialType: kyc.Type,
			Require:        []verification.Requirement{{Claim: kyc.ClaimVerified, Equals: true}},
		},
	}
	return schemas, policies, nil
}
