// Command onchaininspect is a read-only HTTP view of what the credential
// registry program holds on Solana, for looking at the demo's on-chain data with
// curl. It needs no keys and changes nothing.
//
//	go run ./cmd/onchaininspect -program <program id> [-rpc http://127.0.0.1:8899] [-addr 127.0.0.1:9100]
//
//	curl localhost:9100/registry
//	curl localhost:9100/issuers
//	curl localhost:9100/credentials
//
// Only hashes and status are ever on chain: issuer and credential ids appear as
// their SHA-256-derived ids, and the claims inside a credential never do.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
)

// chain is the part of the blockchain client the inspector reads.
type chain interface {
	GetRegistry(ctx context.Context) (blockchain.RegistryConfig, error)
	ListIssuers(ctx context.Context) ([]blockchain.Stored[registry.IssuerRecord], error)
	ListCredentials(ctx context.Context) ([]blockchain.Stored[registry.CredentialStatus], error)
}

func main() {
	addr := flag.String("addr", envOr("INSPECT_ADDR", "127.0.0.1:9100"), "listen address (env INSPECT_ADDR)")
	rpcURL := flag.String("rpc", envOr("SOLANA_RPC_URL", "http://127.0.0.1:8899"), "Solana JSON-RPC URL (env SOLANA_RPC_URL)")
	program := flag.String("program", os.Getenv("SOLANA_PROGRAM_ID"), "registry program id (env SOLANA_PROGRAM_ID)")
	flag.Parse()

	if *program == "" {
		log.Fatal("-program (or SOLANA_PROGRAM_ID) is required")
	}
	client, err := blockchain.NewClient(blockchain.Config{RPCURL: *rpcURL, ProgramID: *program})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           routes(client),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      45 * time.Second,
	}
	log.Printf("onchaininspect: program %s on %s, listening on http://%s", *program, *rpcURL, *addr)
	log.Fatal(srv.ListenAndServe())
}

func routes(c chain) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /registry", func(w http.ResponseWriter, r *http.Request) { registryView(w, r, c) })
	mux.HandleFunc("GET /issuers", func(w http.ResponseWriter, r *http.Request) { issuersView(w, r, c) })
	mux.HandleFunc("GET /credentials", func(w http.ResponseWriter, r *http.Request) { credentialsView(w, r, c) })
	return mux
}

func registryView(w http.ResponseWriter, r *http.Request, c chain) {
	cfg, err := c.GetRegistry(r.Context())
	switch {
	case errors.Is(err, registry.ErrNotFound):
		write(w, http.StatusOK, map[string]any{"initialized": false})
	case err != nil:
		fail(w, err)
	default:
		write(w, http.StatusOK, map[string]any{
			"initialized": true,
			"authority":   cfg.Authority.String(),
			"paused":      cfg.Paused,
			"version":     cfg.Version,
		})
	}
}

func issuersView(w http.ResponseWriter, r *http.Request, c chain) {
	list, err := c.ListIssuers(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, i := range list {
		rec := i.Record
		out = append(out, map[string]any{
			"account":     i.Address.String(),
			"issuer_id":   hex.EncodeToString(rec.IssuerID[:]),
			"signing_key": base64.RawURLEncoding.EncodeToString(rec.SigningKey),
			"authority":   blockchain.Address(rec.Authority),
			"active":      rec.Active,
			"created_at":  rec.CreatedAt.Format(time.RFC3339),
		})
	}
	write(w, http.StatusOK, out)
}

func credentialsView(w http.ResponseWriter, r *http.Request, c chain) {
	list, err := c.ListCredentials(r.Context())
	if err != nil {
		fail(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, cred := range list {
		rec := cred.Record
		state := "active"
		if rec.State == registry.CredentialRevoked {
			state = "revoked"
		}
		out = append(out, map[string]any{
			"account":    cred.Address.String(),
			"ref":        hex.EncodeToString(rec.Ref[:]),
			"issuer_id":  hex.EncodeToString(rec.IssuerID[:]),
			"state":      state,
			"expires_at": rec.ExpiresAt.Format(time.RFC3339),
		})
	}
	write(w, http.StatusOK, out)
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func fail(w http.ResponseWriter, err error) {
	log.Printf("onchaininspect: %v", err)
	write(w, http.StatusBadGateway, map[string]string{"error": "could not read the registry from the Solana RPC node"})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
