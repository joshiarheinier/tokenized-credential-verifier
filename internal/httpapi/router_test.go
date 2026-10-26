package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func do(t *testing.T, h http.Handler, method, path string) (*httptest.ResponseRecorder, statusResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var body statusResponse
	if rec.Body.Len() > 0 && rec.Header().Get("Content-Type") == "application/json" {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body %q: %v", rec.Body.String(), err)
		}
	}
	return rec, body
}

func TestHealthz(t *testing.T) {
	rec, body := do(t, NewRouter(discardLogger()), http.MethodGet, "/healthz")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body.Status != "ok" {
		t.Errorf("body.status = %q, want ok", body.Status)
	}
}

func TestHealthzRejectsOtherMethods(t *testing.T) {
	rec, _ := do(t, NewRouter(discardLogger()), http.MethodPost, "/healthz")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	ok := ReadinessCheck{Name: "db", Check: func(context.Context) error { return nil }}
	bad := ReadinessCheck{Name: "solana", Check: func(context.Context) error { return errors.New("rpc down") }}

	tests := []struct {
		name       string
		checks     []ReadinessCheck
		wantCode   int
		wantStatus string
		wantChecks map[string]string
	}{
		{"no checks", nil, http.StatusOK, "ready", nil},
		{"all pass", []ReadinessCheck{ok}, http.StatusOK, "ready", map[string]string{"db": "ok"}},
		{"one fails", []ReadinessCheck{ok, bad}, http.StatusServiceUnavailable, "not_ready",
			map[string]string{"db": "ok", "solana": "fail"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, body := do(t, NewRouter(discardLogger(), tt.checks...), http.MethodGet, "/readyz")
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if body.Status != tt.wantStatus {
				t.Errorf("body.status = %q, want %q", body.Status, tt.wantStatus)
			}
			if len(body.Checks) != len(tt.wantChecks) {
				t.Fatalf("body.checks = %v, want %v", body.Checks, tt.wantChecks)
			}
			for k, v := range tt.wantChecks {
				if body.Checks[k] != v {
					t.Errorf("checks[%s] = %q, want %q", k, body.Checks[k], v)
				}
			}
		})
	}
}

func TestReadyzDoesNotLeakErrorDetails(t *testing.T) {
	bad := ReadinessCheck{Name: "db", Check: func(context.Context) error { return errors.New("password=hunter2") }}
	rec, _ := do(t, NewRouter(discardLogger(), bad), http.MethodGet, "/readyz")
	if got := rec.Body.String(); strings.Contains(got, "hunter2") {
		t.Fatalf("response leaks check error: %s", got)
	}
}

func TestRecoverPanics(t *testing.T) {
	h := recoverPanics(discardLogger(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestUnknownRoute(t *testing.T) {
	rec, _ := do(t, NewRouter(discardLogger()), http.MethodGet, "/nope")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
