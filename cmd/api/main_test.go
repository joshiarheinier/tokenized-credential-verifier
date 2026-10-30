package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/config"
)

func TestServeAndGracefulShutdown(t *testing.T) {
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := newServer(cfg, logger)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv, ln, cfg, logger) }()

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned %v, want nil after shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after context cancellation")
	}
}

func TestLoadEnvFile(t *testing.T) {
	t.Setenv("ENVFILE_EXISTING", "from-environment")
	path := filepath.Join(t.TempDir(), "demo.env")
	content := "# a comment\n\nENVFILE_NEW = from-file\nENVFILE_EXISTING=from-file\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Unsetenv("ENVFILE_NEW") })

	if err := loadEnvFile(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("ENVFILE_NEW"); got != "from-file" {
		t.Errorf("ENVFILE_NEW = %q, want from-file", got)
	}
	if got := os.Getenv("ENVFILE_EXISTING"); got != "from-environment" {
		t.Errorf("ENVFILE_EXISTING = %q, want the real environment to win", got)
	}
}

func TestLoadEnvFileRejectsBadLinesWithoutQuotingThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(path, []byte("SECRET-without-equals\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := loadEnvFile(path)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v, want an error that does not quote the line", err)
	}
}
