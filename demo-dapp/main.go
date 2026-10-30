package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", envOr("DAPP_ADDR", "127.0.0.1:9090"), "listen address (env DAPP_ADDR)")
	verifierURL := flag.String("verifier", envOr("VERIFIER_URL", "http://127.0.0.1:8080"), "base URL of the credential verifier API (env VERIFIER_URL)")
	flag.Parse()

	h := &history{out: os.Stdout}
	a := &app{
		verifier: verifier{baseURL: *verifierURL, client: &http.Client{Timeout: verifierTimeout}},
		log:      h.add,
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      verifierTimeout + 5*time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("demo-dapp listening on http://%s, verifying through %s", *addr, *verifierURL)

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
