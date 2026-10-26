package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/joshia/tokenized-identity-kyc/internal/config"
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
	a, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, ln) }()

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
			t.Fatalf("Serve returned %v, want nil after shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}
