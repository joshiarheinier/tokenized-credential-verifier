package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != EnvDevelopment {
		t.Errorf("Env = %q, want %q", cfg.Env, EnvDevelopment)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("HTTP.Addr = %q, want :8080", cfg.HTTP.Addr)
	}
	if cfg.HTTP.ShutdownTimeout != 15*time.Second {
		t.Errorf("HTTP.ShutdownTimeout = %v, want 15s", cfg.HTTP.ShutdownTimeout)
	}
	if cfg.Log.Level != slog.LevelInfo || cfg.Log.Format != "json" {
		t.Errorf("Log = %+v, want info/json", cfg.Log)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"APP_ENV":                 "production",
		"SOLANA_RPC_URL":          "https://rpc.example",
		"SOLANA_PROGRAM_ID":       "p",
		"ISSUER_SIGNING_KEY_SEED": "seed",
		"HTTP_ADDR":               "127.0.0.1:9000",
		"HTTP_READ_TIMEOUT":       "3s",
		"LOG_LEVEL":               "debug",
		"LOG_FORMAT":              "TEXT",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != EnvProduction {
		t.Errorf("Env = %q, want production", cfg.Env)
	}
	if cfg.HTTP.Addr != "127.0.0.1:9000" {
		t.Errorf("HTTP.Addr = %q", cfg.HTTP.Addr)
	}
	if cfg.HTTP.ReadTimeout != 3*time.Second {
		t.Errorf("HTTP.ReadTimeout = %v, want 3s", cfg.HTTP.ReadTimeout)
	}
	if cfg.Log.Level != slog.LevelDebug || cfg.Log.Format != "text" {
		t.Errorf("Log = %+v, want debug/text", cfg.Log)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	_, err := Load(env(map[string]string{
		"APP_ENV":            "staging",
		"HTTP_WRITE_TIMEOUT": "soon",
		"HTTP_IDLE_TIMEOUT":  "-1s",
		"LOG_LEVEL":          "loud",
		"LOG_FORMAT":         "xml",
	}))
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	for _, key := range []string{"APP_ENV", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "LOG_LEVEL", "LOG_FORMAT"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %s", err, key)
		}
	}
}

func TestLoadIssuerAndSimulationDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Issuer.ID == "" || cfg.Issuer.CredentialTTL != 30*24*time.Hour {
		t.Errorf("Issuer = %+v", cfg.Issuer)
	}
	if !cfg.Simulation.Enabled {
		t.Error("simulation should default to enabled in development")
	}
}

func TestLoadProductionGuards(t *testing.T) {
	_, err := Load(env(map[string]string{"APP_ENV": "production", "APPROVAL_SIMULATION_ENABLED": "true"}))
	if err == nil {
		t.Fatal("want error for simulation + missing seed in production")
	}
	for _, key := range []string{"APPROVAL_SIMULATION_ENABLED", "ISSUER_SIGNING_KEY_SEED"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %s", err, key)
		}
	}

	cfg, err := Load(env(map[string]string{"APP_ENV": "production", "ISSUER_SIGNING_KEY_SEED": "x", "SOLANA_RPC_URL": "u", "SOLANA_PROGRAM_ID": "p"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Simulation.Enabled {
		t.Error("simulation must default to disabled in production")
	}
}

func TestSolanaDefaultsToDisabled(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Solana
	if s.RPCURL != "" || s.Bootstrap || s.Commitment != "confirmed" ||
		s.RequestTimeout != 10*time.Second || s.TxTimeout != 30*time.Second {
		t.Errorf("Solana = %+v, want chain disabled with safe defaults", s)
	}
}

func TestSolanaValidation(t *testing.T) {
	const url = "http://127.0.0.1:8899"
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string // substring naming the offending variable; empty = valid
	}{
		{"url without program id", map[string]string{"SOLANA_RPC_URL": url, "APPROVAL_SIMULATION_ENABLED": "false"}, "SOLANA_PROGRAM_ID"},
		{"issuance without issuer authority", map[string]string{"SOLANA_RPC_URL": url, "SOLANA_PROGRAM_ID": "p"}, "SOLANA_ISSUER_AUTHORITY_KEYPAIR"},
		{"bootstrap without url", map[string]string{"SOLANA_BOOTSTRAP": "true"}, "SOLANA_BOOTSTRAP"},
		{"bootstrap without keypairs", map[string]string{"SOLANA_RPC_URL": url, "SOLANA_PROGRAM_ID": "p", "SOLANA_ISSUER_AUTHORITY_KEYPAIR": "i", "SOLANA_BOOTSTRAP": "true"}, "SOLANA_BOOTSTRAP"},
		{"processed commitment is refused", map[string]string{"SOLANA_COMMITMENT": "processed"}, "SOLANA_COMMITMENT"},
		{"verification-only needs no keys", map[string]string{"SOLANA_RPC_URL": url, "SOLANA_PROGRAM_ID": "p", "APPROVAL_SIMULATION_ENABLED": "false"}, ""},
		{"full dev setup", map[string]string{"SOLANA_RPC_URL": url, "SOLANA_PROGRAM_ID": "p", "SOLANA_ISSUER_AUTHORITY_KEYPAIR": "i", "SOLANA_REGISTRY_AUTHORITY_KEYPAIR": "r", "SOLANA_BOOTSTRAP": "true", "ISSUER_SIGNING_KEY_SEED": "s"}, ""},
		{"bootstrap with an ephemeral issuer key", map[string]string{"SOLANA_RPC_URL": url, "SOLANA_PROGRAM_ID": "p", "SOLANA_ISSUER_AUTHORITY_KEYPAIR": "i", "SOLANA_REGISTRY_AUTHORITY_KEYPAIR": "r", "SOLANA_BOOTSTRAP": "true"}, "ISSUER_SIGNING_KEY_SEED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(env(tc.env))
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("err = %v, want it to mention %s", err, tc.wantErr)
			}
		})
	}
}

func TestProductionRequiresTheChain(t *testing.T) {
	base := map[string]string{"APP_ENV": "production", "ISSUER_SIGNING_KEY_SEED": "x"}

	_, err := Load(env(base))
	if err == nil || !strings.Contains(err.Error(), "SOLANA_RPC_URL") {
		t.Fatalf("err = %v, want production to require SOLANA_RPC_URL", err)
	}

	withChain := map[string]string{"SOLANA_RPC_URL": "https://rpc.example", "SOLANA_PROGRAM_ID": "p"}
	for k, v := range base {
		withChain[k] = v
	}
	if _, err := Load(env(withChain)); err != nil {
		t.Fatalf("production with chain: %v", err)
	}

	withChain["SOLANA_BOOTSTRAP"] = "true"
	withChain["SOLANA_REGISTRY_AUTHORITY_KEYPAIR"] = "r"
	withChain["SOLANA_ISSUER_AUTHORITY_KEYPAIR"] = "i"
	if _, err := Load(env(withChain)); err == nil || !strings.Contains(err.Error(), "SOLANA_BOOTSTRAP") {
		t.Fatalf("err = %v, want bootstrap refused in production", err)
	}
}

func TestChallengeAndCORSSettings(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Challenge.TTL != 5*time.Minute || len(cfg.HTTP.CORSAllowedOrigins) != 0 {
		t.Errorf("defaults = %v, %v, want 5m and no origins", cfg.Challenge.TTL, cfg.HTTP.CORSAllowedOrigins)
	}

	cfg, err = Load(env(map[string]string{
		"CHALLENGE_TTL":        "90s",
		"CORS_ALLOWED_ORIGINS": " http://localhost:9091 , https://wallet.example,",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Challenge.TTL != 90*time.Second {
		t.Errorf("ChallengeTTL = %v, want 90s", cfg.Challenge.TTL)
	}
	if got := strings.Join(cfg.HTTP.CORSAllowedOrigins, "|"); got != "http://localhost:9091|https://wallet.example" {
		t.Errorf("origins = %q", got)
	}

	for _, bad := range []string{"localhost:9091", "http://localhost:9091/path", "ftp://x.example", "*"} {
		if _, err := Load(env(map[string]string{"CORS_ALLOWED_ORIGINS": bad})); err == nil || !strings.Contains(err.Error(), "CORS_ALLOWED_ORIGINS") {
			t.Errorf("%q: err = %v, want a CORS_ALLOWED_ORIGINS error", bad, err)
		}
	}
}
