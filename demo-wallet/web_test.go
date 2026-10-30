package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
)

func newWebServer(t *testing.T) *httptest.Server {
	t.Helper()
	h, err := webHandler(webConfig{Verifier: "http://127.0.0.1:8080/", Issuer: "http://127.0.0.1:8081"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// get requests target as a browser at http://localhost:<port> would.
func get(t *testing.T, target string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := neturl.Parse(target)
	req.Host = "localhost:" + u.Port()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestWalletPagesAreServed(t *testing.T) {
	srv := newWebServer(t)
	for path, want := range map[string]string{
		"/":             "Demo wallet",
		"/present":      "Share a credential",
		"/present.html": "Share a credential",
	} {
		resp, body := get(t, srv.URL+path)
		if resp.StatusCode != 200 || !strings.Contains(body, want) {
			t.Errorf("%s = %d, want a page containing %q", path, resp.StatusCode, want)
		}
	}
	if resp, _ := get(t, srv.URL+"/nope"); resp.StatusCode != 404 {
		t.Errorf("/nope = %d, want 404", resp.StatusCode)
	}
}

// Browsers refuse ES modules served with another type, and on Windows Go can
// pick text/plain for .js from the registry.
func TestScriptsAreServedAsJavaScript(t *testing.T) {
	srv := newWebServer(t)
	for path, want := range map[string]string{
		"/js/protocol.js": "text/javascript",
		"/js/present.js":  "text/javascript",
		"/style.css":      "text/css",
	} {
		resp, _ := get(t, srv.URL+path)
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), want) {
			t.Errorf("%s = %d %q, want %s", path, resp.StatusCode, resp.Header.Get("Content-Type"), want)
		}
	}
}

func TestPageIsToldWhichBackendToUse(t *testing.T) {
	srv := newWebServer(t)
	resp, body := get(t, srv.URL+"/config.json")
	var cfg map[string]string
	if err := json.Unmarshal([]byte(body), &cfg); err != nil || resp.StatusCode != 200 {
		t.Fatalf("config.json = %d %q: %v", resp.StatusCode, body, err)
	}
	if cfg["verifier"] != "http://127.0.0.1:8080" || cfg["issuer"] != "http://127.0.0.1:8081" {
		t.Errorf("config = %v, want both URLs without a trailing slash", cfg)
	}
}

func TestPagesCarryASecurityPolicy(t *testing.T) {
	srv := newWebServer(t)
	resp, _ := get(t, srv.URL+"/")
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'none'",
		"script-src 'self'",
		"connect-src 'self' http://127.0.0.1:8080 http://127.0.0.1:8081",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("policy %q lacks %q", csp, want)
		}
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing Referrer-Policy: no-referrer or X-Content-Type-Options: nosniff")
	}
}

func TestBadBackendURLsAreRefused(t *testing.T) {
	for _, bad := range []string{"", "localhost:8080", "ftp://x.example", "http://"} {
		if _, err := webHandler(webConfig{Verifier: bad, Issuer: "http://127.0.0.1:8080"}); err == nil {
			t.Errorf("verifier %q accepted", bad)
		}
	}
}

// Browsers keep credentials per web address: 127.0.0.1 and localhost would be two
// separate wallets, so one address is sent to the other.
func TestLoopbackIPIsRedirectedToLocalhost(t *testing.T) {
	srv := newWebServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/present?challenge=abc") // srv.URL is http://127.0.0.1:<port>
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://127.0.0.1"), ":")
	want := "http://localhost:" + port + "/present?challenge=abc"
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != want {
		t.Fatalf("got %d to %q, want a redirect to %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
}
