package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", envOr("DAPP_ADDR", "127.0.0.1:9090"), "listen address (env DAPP_ADDR)")
	verifierURL := flag.String("verifier", envOr("VERIFIER_URL", "http://127.0.0.1:8080"), "base URL of the credential verifier API (env VERIFIER_URL)")
	publicURL := flag.String("public-url", envOr("DAPP_PUBLIC_URL", ""), "this app's own origin as the browser sees it (env DAPP_PUBLIC_URL; default: http://localhost plus the port of -addr)")
	walletURL := flag.String("wallet", envOr("WALLET_URL", "http://localhost:9091"), "origin of the wallet web app (env WALLET_URL)")
	flag.Parse()
	if *publicURL == "" {
		*publicURL = defaultPublicURL(*addr)
	}

	h := &history{out: os.Stdout}
	a := &app{
		verifier: verifier{baseURL: *verifierURL, client: &http.Client{Timeout: verifierTimeout}},
		log:      h.add,
	}
	site := &site{app: a, audience: strings.TrimRight(*publicURL, "/"), wallet: strings.TrimRight(*walletURL, "/"), sessions: newSessions(maxSessions, sessionTTL)}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           site.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      verifierTimeout + 5*time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("demo-dapp on %s (listening on %s), verifier %s, wallet %s", site.audience, *addr, *verifierURL, site.wallet)

	if repl(os.Stdin, os.Stdout, a, h) {
		_ = srv.Close()
		return
	}
	log.Fatal(<-errc) // no terminal to read commands from: just keep serving
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// defaultPublicURL is http://localhost:<port>: the wallet, the session cookie and
// Phantom all go by "localhost", not 127.0.0.1.
func defaultPublicURL(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://localhost:9090"
	}
	return "http://localhost:" + port
}
