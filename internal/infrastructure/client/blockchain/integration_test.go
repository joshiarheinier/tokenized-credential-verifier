//go:build integration

// Integration tests against a real solana-test-validator running the deployed
// registry program. Run them with scripts/integration-test.sh, which starts the
// validator and sets:
//
//	CREDENTIAL_TEST_RPC_URL              validator JSON-RPC endpoint
//	CREDENTIAL_TEST_PROGRAM_ID           deployed registry program id
//	CREDENTIAL_TEST_AUTHORITY_KEYPAIR    keypair that is the program's upgrade authority
package blockchain_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/infrastructure/client/blockchain"
)

type env struct {
	rpcURL    string
	programID string
	registry  solana.PrivateKey
	issuer    solana.PrivateKey
	client    *blockchain.Client
}

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; run scripts/integration-test.sh", key)
	}
	return v
}

func airdrop(t *testing.T, url string, to solana.PublicKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := rpc.New(url)
	if _, err := c.RequestAirdrop(ctx, to, 5*solana.LAMPORTS_PER_SOL, rpc.CommitmentConfirmed); err != nil {
		t.Fatalf("airdrop: %v", err)
	}
	for ctx.Err() == nil {
		bal, err := c.GetBalance(ctx, to, rpc.CommitmentConfirmed)
		if err == nil && bal.Value > 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("airdrop never arrived")
}

func newClient(t *testing.T, cfg blockchain.Config) *blockchain.Client {
	t.Helper()
	c, err := blockchain.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// writeKeypair stores key in solana-keygen JSON format for Config to load.
func writeKeypair(t *testing.T, key solana.PrivateKey) string {
	t.Helper()
	raw, err := json.Marshal([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keypair.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{
		rpcURL:    requireEnv(t, "CREDENTIAL_TEST_RPC_URL"),
		programID: requireEnv(t, "CREDENTIAL_TEST_PROGRAM_ID"),
	}
	registryPath := requireEnv(t, "CREDENTIAL_TEST_AUTHORITY_KEYPAIR")
	var err error
	if e.registry, err = blockchain.LoadKeypair(registryPath); err != nil {
		t.Fatal(err)
	}
	e.issuer = solana.NewWallet().PrivateKey
	airdrop(t, e.rpcURL, e.registry.PublicKey())
	airdrop(t, e.rpcURL, e.issuer.PublicKey())

	e.client = newClient(t, blockchain.Config{
		RPCURL:                   e.rpcURL,
		ProgramID:                e.programID,
		RegistryAuthorityKeypair: registryPath,
		IssuerAuthorityKeypair:   writeKeypair(t, e.issuer),
	})
	return e
}

func newIssuerKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func randomRef(t *testing.T) [32]byte {
	t.Helper()
	var r [32]byte
	if _, err := rand.Read(r[:]); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRegistryLifecycle(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	t.Run("registry initialization is idempotent", func(t *testing.T) {
		// Other test packages share this validator and may have initialized the
		// registry already, so don't assume whether this call creates it.
		res, err := e.client.InitializeRegistry(ctx)
		if err != nil || (res.Changed && res.Reference == "") {
			t.Fatalf("init: res=%+v err=%v", res, err)
		}
		cfg, err := e.client.GetRegistry(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Authority != e.registry.PublicKey() || cfg.Paused || cfg.Version != 1 {
			t.Fatalf("registry = %+v", cfg)
		}
		if res, err := e.client.InitializeRegistry(ctx); err != nil || res.Changed {
			t.Fatalf("repeat init: res=%+v err=%v, want no-op", res, err)
		}
	})

	issuerID := registry.IssuerID("did:example:integration-issuer")
	signingKey := newIssuerKey(t)

	t.Run("issuer registration and lookup", func(t *testing.T) {
		if _, err := e.client.GetIssuer(ctx, issuerID); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("before register: err = %v, want ErrNotFound", err)
		}
		res, err := e.client.RegisterIssuer(ctx, issuerID, signingKey, e.issuer.PublicKey())
		if err != nil || !res.Changed {
			t.Fatalf("register: res=%+v err=%v", res, err)
		}
		rec, err := e.client.GetIssuer(ctx, issuerID)
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Active || !signingKey.Equal(rec.SigningKey) || rec.Authority != e.issuer.PublicKey() || rec.IssuerID != issuerID {
			t.Fatalf("issuer = %+v", rec)
		}

		if res, err := e.client.RegisterIssuer(ctx, issuerID, signingKey, e.issuer.PublicKey()); err != nil || res.Changed {
			t.Fatalf("identical repeat: res=%+v err=%v, want no-op", res, err)
		}
		if _, err := e.client.RegisterIssuer(ctx, issuerID, newIssuerKey(t), e.issuer.PublicKey()); !errors.Is(err, registry.ErrConflict) {
			t.Fatalf("different key: err = %v, want ErrConflict", err)
		}
	})

	ref := randomRef(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)

	t.Run("credential registration and lookup", func(t *testing.T) {
		if _, err := e.client.GetCredentialStatus(ctx, ref); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("before register: err = %v, want ErrNotFound", err)
		}
		res, err := e.client.RegisterCredential(ctx, issuerID, ref, exp)
		if err != nil || !res.Changed {
			t.Fatalf("register: res=%+v err=%v", res, err)
		}
		st, err := e.client.GetCredentialStatus(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		if st.State != registry.CredentialActive || st.IssuerID != issuerID || !st.ExpiresAt.Equal(exp) {
			t.Fatalf("status = %+v", st)
		}
		creds, err := e.client.ListCredentials(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(creds, func(c blockchain.Stored[registry.CredentialStatus]) bool { return c.Record == st }) {
			t.Fatalf("ListCredentials does not contain %+v", st)
		}
		issuers, err := e.client.ListIssuers(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(issuers, func(i blockchain.Stored[registry.IssuerRecord]) bool { return i.Record.IssuerID == issuerID }) {
			t.Fatal("ListIssuers does not contain the registered issuer")
		}
		if res, err := e.client.RegisterCredential(ctx, issuerID, ref, exp); err != nil || res.Changed {
			t.Fatalf("identical repeat: res=%+v err=%v, want no-op", res, err)
		}
		if _, err := e.client.RegisterCredential(ctx, issuerID, ref, exp.Add(time.Hour)); !errors.Is(err, registry.ErrConflict) {
			t.Fatalf("different expiry: err = %v, want ErrConflict", err)
		}
	})

	t.Run("concurrent identical registrations do not conflict", func(t *testing.T) {
		ref := randomRef(t)
		const n = 5
		var wg sync.WaitGroup
		results := make([]registry.WriteResult, n)
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i], errs[i] = e.client.RegisterCredential(ctx, issuerID, ref, exp)
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("request %d: %v", i, err)
			}
		}
		if st, err := e.client.GetCredentialStatus(ctx, ref); err != nil || st.State != registry.CredentialActive {
			t.Fatalf("status = %+v err=%v", st, err)
		}
	})

	t.Run("suspended issuer cannot register credentials", func(t *testing.T) {
		if res, err := e.client.SetIssuerStatus(ctx, issuerID, false); err != nil || !res.Changed {
			t.Fatalf("suspend: res=%+v err=%v", res, err)
		}
		rec, _ := e.client.GetIssuer(ctx, issuerID)
		if rec.Active {
			t.Fatal("issuer should be inactive")
		}
		_, err := e.client.RegisterCredential(ctx, issuerID, randomRef(t), exp)
		if !errors.Is(err, blockchain.ErrTxRejected) {
			t.Fatalf("err = %v, want ErrTxRejected (the program must enforce this, not the client)", err)
		}
		if res, err := e.client.SetIssuerStatus(ctx, issuerID, false); err != nil || res.Changed {
			t.Fatalf("suspend again: res=%+v err=%v, want no-op", res, err)
		}
		if _, err := e.client.SetIssuerStatus(ctx, issuerID, true); err != nil {
			t.Fatalf("reactivate: %v", err)
		}
	})

	t.Run("revocation", func(t *testing.T) {
		if _, err := e.client.RevokeCredential(ctx, issuerID, randomRef(t)); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("unknown credential: err = %v, want ErrNotFound", err)
		}
		res, err := e.client.RevokeCredential(ctx, issuerID, ref)
		if err != nil || !res.Changed {
			t.Fatalf("revoke: res=%+v err=%v", res, err)
		}
		if st, _ := e.client.GetCredentialStatus(ctx, ref); st.State != registry.CredentialRevoked {
			t.Fatalf("status = %+v, want revoked", st)
		}
		if res, err := e.client.RevokeCredential(ctx, issuerID, ref); err != nil || res.Changed {
			t.Fatalf("revoke again: res=%+v err=%v, want no-op", res, err)
		}
	})

	t.Run("program rejects an unauthorized signer", func(t *testing.T) {
		// A client whose "registry authority" is not the registry's authority:
		// the Go client has no say, the program must refuse.
		rogue := solana.NewWallet().PrivateKey
		airdrop(t, e.rpcURL, rogue.PublicKey())
		c := newClient(t, blockchain.Config{
			RPCURL:                   e.rpcURL,
			ProgramID:                e.programID,
			RegistryAuthorityKeypair: writeKeypair(t, rogue),
		})

		_, err := c.RegisterIssuer(ctx, registry.IssuerID("did:example:rogue"), newIssuerKey(t), rogue.PublicKey())
		if !errors.Is(err, blockchain.ErrTxRejected) {
			t.Fatalf("err = %v, want ErrTxRejected", err)
		}
		if _, err := e.client.GetIssuer(ctx, registry.IssuerID("did:example:rogue")); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("rogue issuer must not exist, got err = %v", err)
		}
	})
}
