// Command api runs the credential verifier backend HTTP server. It is the
// composition root: it loads configuration, builds every dependency, wires them
// together and owns the process lifecycle.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/approval"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/application/verification"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
	domaincredential "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/credential/kyc"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/issuer"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
	domainverification "github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/verification"
	httpgateway "github.com/joshiarheinier/tokenized-credential-verifier/internal/gateways/http"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	envFile := flag.String("env-file", "", "load KEY=VALUE lines from this file into the environment (development convenience)")
	flag.Parse()
	if *envFile != "" {
		if err := loadEnvFile(*envFile); err != nil {
			return err
		}
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, cfg.Log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := newServer(cfg, logger)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTP.Addr, err)
	}
	if err := serve(ctx, srv, ln, cfg, logger); err != nil {
		logger.Error("api exited with error", "error", err)
		return err
	}
	return nil
}

// loadEnvFile sets each KEY=VALUE line of path in the process environment,
// skipping blank lines and # comments. Variables that are already set win, so a
// real environment variable overrides the file. Errors never quote the file's
// contents, which may be secrets.
func loadEnvFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("env file: %w", err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return fmt.Errorf("env file %s: line %d is not KEY=VALUE", path, i+1)
		}
		if _, set := os.LookupEnv(key); !set {
			if err := os.Setenv(key, strings.TrimSpace(value)); err != nil {
				return fmt.Errorf("env file: %w", err)
			}
		}
	}
	return nil
}

// newServer assembles the HTTP server from its configuration.
func newServer(cfg config.Config, logger *slog.Logger) (*http.Server, error) {
	api, err := buildAPI(cfg, logger)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Handler:           httpgateway.NewRouter(logger, api),
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}, nil
}

// buildAPI constructs the application services and hands them to the HTTP
// gateway. A service that is not enabled is left nil, so its routes are not
// registered.
func buildAPI(cfg config.Config, logger *slog.Logger) (httpgateway.API, error) {
	seed := cfg.Issuer.SigningKeySeed
	if seed == "" {
		// config.Load guarantees this only happens outside production.
		var err error
		if seed, err = issuer.GenerateSeed(); err != nil {
			return httpgateway.API{}, err
		}
		logger.Warn("ISSUER_SIGNING_KEY_SEED not set: using an ephemeral issuer key; issued credentials will not verify after restart")
	}
	iss, err := issuer.New(cfg.Issuer.ID, seed)
	if err != nil {
		return httpgateway.API{}, fmt.Errorf("issuer: %w", err)
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
			return httpgateway.API{}, err
		}
		verifyOpts = append(verifyOpts, verification.WithBlockchainClient(chain))
		issueOpts = append(issueOpts, credential.WithBlockchainClient(chain))
		logger.Info("on-chain registry enabled", "rpc_url", cfg.Solana.RPCURL, "program_id", cfg.Solana.ProgramID, "commitment", cfg.Solana.Commitment)
		if cfg.Solana.Bootstrap {
			if err := bootstrapRegistry(chain, iss, cfg.Solana.TxTimeout, logger); err != nil {
				return httpgateway.API{}, err
			}
		}
	} else {
		logger.Warn("SOLANA_RPC_URL not set: credentials are verified off-chain only, with no issuer trust or revocation check")
	}

	schemas, policies, err := credentialTypes(iss.ID)
	if err != nil {
		return httpgateway.API{}, err
	}
	verifier := domaincredential.NewVerifier(schemas, nil)
	verifier.Trust(iss.ID, iss.Signer.PublicKey())
	api := httpgateway.API{CredentialVerification: verification.NewService(verifier, policies, verifyOpts...)}

	if cfg.Simulation.Enabled {
		logger.Warn("simulated approvals are enabled: for local development only")
		approvals := approval.NewService(schemas)
		issuing, err := credential.NewService(iss.Signer, approvals, schemas, cfg.Issuer.CredentialTTL, nil, issueOpts...)
		if err != nil {
			return httpgateway.API{}, err
		}
		api.ApprovalSimulation = approvals
		api.CredentialIssuance = issuing
	}
	return api, nil
}

// serve serves HTTP on ln until ctx is cancelled, then shuts down gracefully,
// giving in-flight requests up to the configured shutdown timeout to finish.
func serve(ctx context.Context, srv *http.Server, ln net.Listener, cfg config.Config, logger *slog.Logger) error {
	errCh := make(chan error, 1)
	go func() {
		logger.Info("http server listening", "addr", ln.Addr().String(), "env", cfg.Env)
		errCh <- srv.Serve(ln)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutting down http server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http server shutdown: %w", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	logger.Info("http server stopped")
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
	res, err := chain.RegisterIssuer(ctx, registry.IssuerID(iss.ID), iss.Signer.PublicKey(), authority)
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
//
// issuerID is this deployment's own issuer, the only one it trusts today, so
// it is the only issuer each policy accepts.
func credentialTypes(issuerID string) (*domaincredential.Schemas, []domainverification.Policy, error) {
	schemas, err := domaincredential.NewSchemas(kyc.Schema)
	if err != nil {
		return nil, nil, fmt.Errorf("credential types: %w", err)
	}
	policies := []domainverification.Policy{
		{
			CredentialType:  kyc.Type,
			Require:         []domainverification.Requirement{{Claim: kyc.ClaimVerified, Equals: true}},
			AcceptedIssuers: []string{issuerID},
		},
	}
	return schemas, policies, nil
}
