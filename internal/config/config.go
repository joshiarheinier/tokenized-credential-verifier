// Package config loads application configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Environment names the deployment environment the process runs in.
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvTest        Environment = "test"
	EnvProduction  Environment = "production"
)

// Config is the complete runtime configuration of the API process.
type Config struct {
	Env    Environment
	HTTP   HTTPConfig
	Log    LogConfig
	Issuer IssuerConfig
	KYC    KYCConfig
	Solana SolanaConfig
}

// IssuerConfig identifies the credential issuer and its signing key.
type IssuerConfig struct {
	ID string
	// SigningKeySeed is the base64url-encoded 32-byte Ed25519 seed. It is a
	// secret: never log it. Empty means "generate an ephemeral key", which is
	// only allowed outside production.
	SigningKeySeed string
	CredentialTTL  time.Duration
}

// KYCConfig controls the simulated KYC flow.
type KYCConfig struct {
	// SimulationEnabled exposes the simulated KYC and issuance endpoints.
	// It must never be enabled in production.
	SimulationEnabled bool
}

// SolanaConfig configures access to the on-chain registry. An empty RPCURL
// disables the chain, leaving credential checks off-chain only; that is
// refused in production so verification cannot silently skip the registry.
type SolanaConfig struct {
	RPCURL    string
	ProgramID string
	// Commitment is "confirmed" or "finalized".
	Commitment string
	// RegistryAuthorityKeypair and IssuerAuthorityKeypair are paths to
	// solana-keygen JSON files. They are secrets: never log their contents.
	// Verification-only processes need neither.
	RegistryAuthorityKeypair string
	IssuerAuthorityKeypair   string
	RequestTimeout           time.Duration
	TxTimeout                time.Duration
	// Bootstrap makes startup create the registry and register this process's
	// issuer if missing. Development and test only.
	Bootstrap bool
}

// HTTPConfig controls the HTTP server.
type HTTPConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  slog.Level
	Format string // "json" or "text"
}

// Load builds a Config from the given lookup function, normally os.Getenv.
// Unset variables fall back to development-friendly defaults; invalid values
// are reported together so a misconfigured process fails fast at startup.
func Load(getenv func(string) string) (Config, error) {
	l := loader{getenv: getenv}

	cfg := Config{
		Env: Environment(l.str("APP_ENV", string(EnvDevelopment))),
		HTTP: HTTPConfig{
			Addr:            l.str("HTTP_ADDR", ":8080"),
			ReadTimeout:     l.duration("HTTP_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:    l.duration("HTTP_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:     l.duration("HTTP_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: l.duration("HTTP_SHUTDOWN_TIMEOUT", 15*time.Second),
		},
		Log: LogConfig{
			Level:  l.level("LOG_LEVEL", slog.LevelInfo),
			Format: strings.ToLower(l.str("LOG_FORMAT", "json")),
		},
		Issuer: IssuerConfig{
			ID:             l.str("ISSUER_ID", "did:example:issuer-dev"),
			SigningKeySeed: l.str("ISSUER_SIGNING_KEY_SEED", ""),
			CredentialTTL:  l.duration("CREDENTIAL_TTL", 30*24*time.Hour),
		},
	}
	cfg.KYC.SimulationEnabled = l.boolean("KYC_SIMULATION_ENABLED", cfg.Env != EnvProduction)
	cfg.Solana = SolanaConfig{
		RPCURL:                   l.str("SOLANA_RPC_URL", ""),
		ProgramID:                l.str("SOLANA_PROGRAM_ID", ""),
		Commitment:               strings.ToLower(l.str("SOLANA_COMMITMENT", "confirmed")),
		RegistryAuthorityKeypair: l.str("SOLANA_REGISTRY_AUTHORITY_KEYPAIR", ""),
		IssuerAuthorityKeypair:   l.str("SOLANA_ISSUER_AUTHORITY_KEYPAIR", ""),
		RequestTimeout:           l.duration("SOLANA_REQUEST_TIMEOUT", 10*time.Second),
		TxTimeout:                l.duration("SOLANA_TX_TIMEOUT", 30*time.Second),
		Bootstrap:                l.boolean("SOLANA_BOOTSTRAP", false),
	}

	switch cfg.Env {
	case EnvDevelopment, EnvTest, EnvProduction:
	default:
		l.fail("APP_ENV", string(cfg.Env), "must be one of development, test, production")
	}
	switch cfg.Log.Format {
	case "json", "text":
	default:
		l.fail("LOG_FORMAT", cfg.Log.Format, "must be json or text")
	}

	l.validateSolana(cfg)

	if cfg.Env == EnvProduction {
		if cfg.Solana.RPCURL == "" {
			l.fail("SOLANA_RPC_URL", "", "required in production: credentials must be checked against the on-chain registry")
		}
		if cfg.Solana.Bootstrap {
			l.fail("SOLANA_BOOTSTRAP", "true", "registry bootstrap must not be enabled in production")
		}
		if cfg.KYC.SimulationEnabled {
			l.fail("KYC_SIMULATION_ENABLED", "true", "simulated KYC must not be enabled in production")
		}
		if cfg.Issuer.SigningKeySeed == "" {
			l.fail("ISSUER_SIGNING_KEY_SEED", "", "required in production")
		}
	}

	if len(l.errs) > 0 {
		return Config{}, errors.Join(l.errs...)
	}
	return cfg, nil
}

// validateSolana checks the chain settings that depend on each other.
func (l *loader) validateSolana(cfg Config) {
	s := cfg.Solana
	switch s.Commitment {
	case "confirmed", "finalized":
	default:
		l.fail("SOLANA_COMMITMENT", s.Commitment, "must be confirmed or finalized")
	}
	if s.RPCURL == "" {
		if s.Bootstrap {
			l.fail("SOLANA_BOOTSTRAP", "true", "requires SOLANA_RPC_URL")
		}
		return
	}
	if s.ProgramID == "" {
		l.fail("SOLANA_PROGRAM_ID", "", "required when SOLANA_RPC_URL is set")
	}
	if cfg.KYC.SimulationEnabled && s.IssuerAuthorityKeypair == "" {
		l.fail("SOLANA_ISSUER_AUTHORITY_KEYPAIR", "", "required to register issued credentials on chain")
	}
	if s.Bootstrap && (s.RegistryAuthorityKeypair == "" || s.IssuerAuthorityKeypair == "") {
		l.fail("SOLANA_BOOTSTRAP", "true", "requires both authority keypairs")
	}
	if s.Bootstrap && cfg.Issuer.SigningKeySeed == "" {
		// An ephemeral key differs on every start, and the registry refuses to
		// re-register an issuer under a different key.
		l.fail("ISSUER_SIGNING_KEY_SEED", "", "required with SOLANA_BOOTSTRAP so the issuer key is stable across restarts")
	}
}

type loader struct {
	getenv func(string) string
	errs   []error
}

func (l *loader) fail(key, value, reason string) {
	l.errs = append(l.errs, fmt.Errorf("config: %s=%q: %s", key, value, reason))
}

func (l *loader) str(key, def string) string {
	if v := strings.TrimSpace(l.getenv(key)); v != "" {
		return v
	}
	return def
}

func (l *loader) duration(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		l.fail(key, raw, "must be a positive duration such as 10s")
		return def
	}
	return d
}

func (l *loader) boolean(key string, def bool) bool {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return def
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		l.fail(key, raw, "must be true or false")
		return def
	}
	return b
}

func (l *loader) level(key string, def slog.Level) slog.Level {
	raw := strings.TrimSpace(l.getenv(key))
	if raw == "" {
		return def
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(raw)); err != nil {
		l.fail(key, raw, "must be debug, info, warn or error")
		return def
	}
	return lvl
}
