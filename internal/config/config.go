// Package config loads application configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
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
	Env  Environment
	HTTP HTTPConfig
	Log  LogConfig
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

	if len(l.errs) > 0 {
		return Config{}, errors.Join(l.errs...)
	}
	return cfg, nil
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
