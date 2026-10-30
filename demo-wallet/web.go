package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The browser wallet is a static web app: plain JavaScript modules with no build
// step. The Go side only serves the files and tells the page which backend to
// talk to; the page calls the backend itself (the backend must list the
// wallet's origin in CORS_ALLOWED_ORIGINS).
//
//go:embed web
var webFiles embed.FS

func init() {
	// On Windows Go takes MIME types from the registry, where .js is sometimes
	// text/plain, which browsers refuse for ES modules.
	for ext, typ := range map[string]string{
		".js":   "text/javascript; charset=utf-8",
		".css":  "text/css; charset=utf-8",
		".html": "text/html; charset=utf-8",
		".json": "application/json",
	} {
		_ = mime.AddExtensionType(ext, typ)
	}
}

// webConfig is where the page's backend calls go.
type webConfig struct {
	// Verifier is the verifier API base URL. It is the only verifier the wallet
	// will send a credential to, whatever a challenge link says.
	Verifier string
	// Issuer is the credential issuer API base URL.
	Issuer string
}

// webHandler serves the wallet app.
func webHandler(cfg webConfig) (http.Handler, error) {
	site, err := fs.Sub(webFiles, "web")
	if err != nil {
		return nil, err
	}
	policy, err := contentSecurityPolicy(cfg)
	if err != nil {
		return nil, err
	}
	files := http.FileServerFS(site)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /config.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"verifier": strings.TrimRight(cfg.Verifier, "/"),
			"issuer":   strings.TrimRight(cfg.Issuer, "/"),
		})
	})
	// The page a challenge link opens: /present?challenge=<id>
	mux.HandleFunc("GET /present", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/present.html"
		files.ServeHTTP(w, r)
	})
	mux.Handle("/", files)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers keep credentials per web address, so 127.0.0.1 and localhost
		// would be two different, apparently empty wallets (and Phantom and the
		// backend's CORS list expect localhost). Always use localhost.
		if host, port, err := net.SplitHostPort(r.Host); err == nil && host == "127.0.0.1" {
			http.Redirect(w, r, "http://localhost:"+port+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		// The wallet's URL carries a challenge id; do not leak it to the page the
		// user goes back to.
		h.Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	}), nil
}

// contentSecurityPolicy lets the page load only its own scripts and styles and
// talk only to itself and the two configured backends. The wallet shows data
// that comes from outside (challenges, credentials), so this is a second line
// of defence behind never inserting that data as HTML.
func contentSecurityPolicy(cfg webConfig) (string, error) {
	connect := []string{"'self'"}
	for _, raw := range []string{cfg.Verifier, cfg.Issuer} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", fmt.Errorf("%q is not a backend URL such as http://127.0.0.1:8080", raw)
		}
		origin := u.Scheme + "://" + u.Host
		if !contains(connect, origin) {
			connect = append(connect, origin)
		}
	}
	return "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
		"connect-src " + strings.Join(connect, " ") + "; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// serveWeb runs the wallet app until the server stops.
func serveWeb(out io.Writer, addr string, cfg webConfig) error {
	handler, err := webHandler(cfg)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	origin := "http://" + strings.Replace(addr, "127.0.0.1", "localhost", 1)
	fmt.Fprintf(out, "demo-wallet web app on %s\n  verifier %s\n  issuer   %s\n", origin, cfg.Verifier, cfg.Issuer)
	fmt.Fprintf(out, "The backend must allow this origin: CORS_ALLOWED_ORIGINS=%s\n", origin)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
