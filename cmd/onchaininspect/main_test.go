package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
)

type fakeChain struct {
	cfg     blockchain.RegistryConfig
	cfgErr  error
	issuers []blockchain.Stored[registry.IssuerRecord]
	creds   []blockchain.Stored[registry.CredentialStatus]
	err     error
}

func (f fakeChain) GetRegistry(context.Context) (blockchain.RegistryConfig, error) {
	return f.cfg, f.cfgErr
}

func (f fakeChain) ListIssuers(context.Context) ([]blockchain.Stored[registry.IssuerRecord], error) {
	return f.issuers, f.err
}

func (f fakeChain) ListCredentials(context.Context) ([]blockchain.Stored[registry.CredentialStatus], error) {
	return f.creds, f.err
}

func get(t *testing.T, c chain, path string) (int, any) {
	t.Helper()
	rec := httptest.NewRecorder()
	routes(c).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("%s: response is not JSON: %v", path, err)
	}
	return rec.Code, body
}

func TestViewsShowReadableOnChainData(t *testing.T) {
	var id, ref [32]byte
	id[0], ref[0] = 0xab, 0xcd
	c := fakeChain{
		cfg:     blockchain.RegistryConfig{Authority: solana.NewWallet().PublicKey(), Version: 1},
		issuers: []blockchain.Stored[registry.IssuerRecord]{{Record: registry.IssuerRecord{IssuerID: id, SigningKey: make([]byte, 32), Active: true, CreatedAt: time.Unix(0, 0)}}},
		creds:   []blockchain.Stored[registry.CredentialStatus]{{Record: registry.CredentialStatus{Ref: ref, IssuerID: id, State: registry.CredentialRevoked}}},
	}

	if code, body := get(t, c, "/registry"); code != 200 || body.(map[string]any)["initialized"] != true {
		t.Fatalf("/registry = %d %v", code, body)
	}
	if code, body := get(t, c, "/issuers"); code != 200 || body.([]any)[0].(map[string]any)["issuer_id"].(string)[:2] != "ab" {
		t.Fatalf("/issuers = %d %v", code, body)
	}
	if code, body := get(t, c, "/credentials"); code != 200 || body.([]any)[0].(map[string]any)["state"] != "revoked" {
		t.Fatalf("/credentials = %d %v", code, body)
	}
}

func TestUninitializedRegistryAndEmptyListsAreNotErrors(t *testing.T) {
	c := fakeChain{cfgErr: registry.ErrNotFound}
	if code, body := get(t, c, "/registry"); code != 200 || body.(map[string]any)["initialized"] != false {
		t.Fatalf("/registry = %d %v", code, body)
	}
	if code, body := get(t, c, "/issuers"); code != 200 || len(body.([]any)) != 0 {
		t.Fatalf("/issuers = %d %v, want an empty list", code, body)
	}
}

func TestRPCFailureIsReportedNotHidden(t *testing.T) {
	c := fakeChain{err: errors.New("connection refused"), cfgErr: errors.New("connection refused")}
	for _, path := range []string{"/registry", "/issuers", "/credentials"} {
		if code, _ := get(t, c, path); code != http.StatusBadGateway {
			t.Errorf("%s = %d, want 502", path, code)
		}
	}
}
