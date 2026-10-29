package blockchain

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
)

// --- Wire format ------------------------------------------------------------

// Discriminators copied from target/idl/credential_registry.json. If the program's
// instruction or account names change, these fail and the adapter must follow.
func TestDiscriminatorsMatchIDL(t *testing.T) {
	cases := map[string]struct {
		got  [8]byte
		want string
	}{
		"initialize_registry": {ixInitializeRegistry, "bdb51411ae39f93b"},
		"register_issuer":     {ixRegisterIssuer, "9175343bbd1b7f12"},
		"set_issuer_status":   {ixSetIssuerStatus, "1fa04b7377625b0f"},
		"register_credential": {ixRegisterCredential, "017db613b49730e7"},
		"revoke_credential":   {ixRevokeCredential, "267b5f5fdf9ea957"},
		"RegistryConfig":      {acctRegistryConfig, "17760af6ade7f39c"},
		"IssuerRecord":        {acctIssuerRecord, "ead3b1357bdf2a52"},
		"CredentialStatus":    {acctCredentialState, "c1889f078570beda"},
	}
	for name, c := range cases {
		if got := hex.EncodeToString(c.got[:]); got != c.want {
			t.Errorf("%s discriminator = %s, want %s", name, got, c.want)
		}
	}
}

var testProgram = solana.MustPublicKeyFromBase58("6NY7DBX4GQTq25E8pcrxUw4wDtGAC3EX1QVwD8jUDUMy")

func issuerData(id [32]byte, key ed25519.PublicKey, authority solana.PublicKey, active bool, created int64) []byte {
	d := append([]byte{}, acctIssuerRecord[:]...)
	d = append(d, id[:]...)
	d = append(d, key...)
	d = append(d, authority[:]...)
	d = append(d, encodeBool(active))
	d = binary.LittleEndian.AppendUint64(d, uint64(created))
	return append(d, 255)
}

func credentialData(ref, issuer [32]byte, state byte, exp int64) []byte {
	d := append([]byte{}, acctCredentialState[:]...)
	d = append(d, ref[:]...)
	d = append(d, issuer[:]...)
	d = append(d, state)
	d = binary.LittleEndian.AppendUint64(d, uint64(exp))
	return append(d, 254)
}

func registryData(authority solana.PublicKey, paused bool) []byte {
	d := append([]byte{}, acctRegistryConfig[:]...)
	d = append(d, authority[:]...)
	return append(d, encodeBool(paused), 1, 253)
}

func TestDecodeRoundTrip(t *testing.T) {
	id, ref := registry.IssuerID("iss"), registry.CredentialRef("jti")
	pub, _, _ := ed25519.GenerateKey(nil)
	auth := solana.NewWallet().PublicKey()

	iss, err := decodeIssuerRecord(testProgram, testProgram, issuerData(id, pub, auth, true, 1700000000))
	if err != nil {
		t.Fatal(err)
	}
	if iss.IssuerID != id || !pub.Equal(iss.SigningKey) || iss.Authority != auth || !iss.Active || iss.CreatedAt.Unix() != 1700000000 {
		t.Fatalf("issuer decoded wrong: %+v", iss)
	}

	st, err := decodeCredentialStatus(testProgram, testProgram, credentialData(ref, id, 1, 1800000000))
	if err != nil {
		t.Fatal(err)
	}
	if st.Ref != ref || st.IssuerID != id || st.State != registry.CredentialRevoked || st.ExpiresAt.Unix() != 1800000000 {
		t.Fatalf("credential decoded wrong: %+v", st)
	}

	cfg, err := decodeRegistryConfig(testProgram, testProgram, registryData(auth, true))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Authority != auth || !cfg.Paused || cfg.Version != 1 {
		t.Fatalf("registry decoded wrong: %+v", cfg)
	}
}

func TestDecodeRejectsUntrustedAccounts(t *testing.T) {
	id, ref := registry.IssuerID("iss"), registry.CredentialRef("jti")
	pub, _, _ := ed25519.GenerateKey(nil)
	auth := solana.NewWallet().PublicKey()
	other := solana.NewWallet().PublicKey()
	good := issuerData(id, pub, auth, true, 1)

	tamper := func(f func([]byte) []byte) []byte { return f(append([]byte{}, good...)) }
	cases := map[string]struct {
		owner solana.PublicKey
		data  []byte
	}{
		"wrong owner":         {other, good},
		"short":               {testProgram, good[:len(good)-1]},
		"long":                {testProgram, append(append([]byte{}, good...), 0)},
		"wrong discriminator": {testProgram, tamper(func(b []byte) []byte { b[0] ^= 1; return b })},
		"bad bool":            {testProgram, tamper(func(b []byte) []byte { b[104] = 2; return b })},
		"empty":               {testProgram, nil},
	}
	for name, c := range cases {
		if _, err := decodeIssuerRecord(testProgram, c.owner, c.data); !errors.Is(err, ErrInvalidAccount) {
			t.Errorf("issuer/%s: err = %v, want ErrInvalidAccount", name, err)
		}
	}
	if _, err := decodeCredentialStatus(testProgram, testProgram, credentialData(ref, id, 7, 1)); !errors.Is(err, ErrInvalidAccount) {
		t.Errorf("unknown credential status: err = %v, want ErrInvalidAccount", err)
	}
	// An account of the wrong type must not decode as another type.
	if _, err := decodeCredentialStatus(testProgram, testProgram, good); !errors.Is(err, ErrInvalidAccount) {
		t.Errorf("issuer data as credential: err = %v, want ErrInvalidAccount", err)
	}
}

// --- Client with a fake RPC -------------------------------------------------

type fakeRPC struct {
	accounts map[solana.PublicKey]*rpc.Account

	accountErrs  []error // consumed one per GetAccountInfo call
	blockhashErr error
	sendErrs     []error // consumed one per send
	sent         []*solana.Transaction
	onSend       func(*solana.Transaction)

	status    *rpc.SignatureStatusesResult // nil: not yet visible
	height    uint64
	lastValid uint64
}

func newFakeRPC() *fakeRPC {
	return &fakeRPC{
		accounts:  map[solana.PublicKey]*rpc.Account{},
		status:    &rpc.SignatureStatusesResult{ConfirmationStatus: rpc.ConfirmationStatusConfirmed},
		lastValid: 1000,
	}
}

func (f *fakeRPC) put(addr solana.PublicKey, owner solana.PublicKey, data []byte) {
	enc, err := rpc.DataBytesOrJSONFromBase64(base64.StdEncoding.EncodeToString(data))
	if err != nil {
		panic(err)
	}
	f.accounts[addr] = &rpc.Account{Owner: owner, Data: enc}
}

func (f *fakeRPC) GetAccountInfoWithOpts(_ context.Context, addr solana.PublicKey, _ *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	if len(f.accountErrs) > 0 {
		err := f.accountErrs[0]
		f.accountErrs = f.accountErrs[1:]
		return nil, err
	}
	acct, ok := f.accounts[addr]
	if !ok {
		return nil, rpc.ErrNotFound
	}
	return &rpc.GetAccountInfoResult{Value: acct}, nil
}

func (f *fakeRPC) GetLatestBlockhashWithOpts(context.Context, *rpc.GetLatestBlockhashOpts) (*rpc.GetLatestBlockhashResult, error) {
	if f.blockhashErr != nil {
		return nil, f.blockhashErr
	}
	return &rpc.GetLatestBlockhashResult{Value: &rpc.LatestBlockhashResult{LastValidBlockHeight: f.lastValid}}, nil
}

func (f *fakeRPC) SendTransactionWithOpts(_ context.Context, tx *solana.Transaction, _ rpc.TransactionOpts) (solana.Signature, error) {
	if len(f.sendErrs) > 0 {
		err := f.sendErrs[0]
		f.sendErrs = f.sendErrs[1:]
		if err != nil {
			return solana.Signature{}, err
		}
	}
	f.sent = append(f.sent, tx)
	if f.onSend != nil {
		f.onSend(tx)
	}
	return tx.Signatures[0], nil
}

func (f *fakeRPC) GetSignatureStatuses(context.Context, bool, ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{f.status}}, nil
}

func (f *fakeRPC) GetBlockHeight(context.Context, rpc.CommitmentType) (uint64, error) {
	return f.height, nil
}

func testClient(f *fakeRPC) (*Client, solana.PrivateKey, solana.PrivateKey) {
	registryKey, issuer := solana.NewWallet().PrivateKey, solana.NewWallet().PrivateKey
	c := newClient(f, options{
		ProgramID:         testProgram,
		RegistryAuthority: &registryKey,
		IssuerAuthority:   &issuer,
		Attempts:          3,
		Backoff:           time.Millisecond,
	})
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c, registryKey, issuer
}

func (f *fakeRPC) putIssuer(t *testing.T, c *Client, id [32]byte, key ed25519.PublicKey, authority solana.PublicKey, active bool) {
	t.Helper()
	addr, err := c.addrs.issuer(id)
	if err != nil {
		t.Fatal(err)
	}
	f.put(addr, testProgram, issuerData(id, key, authority, active, 1700000000))
}

func (f *fakeRPC) putCredential(t *testing.T, c *Client, ref, issuer [32]byte, state byte, exp int64) {
	t.Helper()
	addr, err := c.addrs.credential(ref)
	if err != nil {
		t.Fatal(err)
	}
	f.put(addr, testProgram, credentialData(ref, issuer, state, exp))
}

func TestGetIssuer(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	id := registry.IssuerID("iss")
	pub, _, _ := ed25519.GenerateKey(nil)
	auth := solana.NewWallet().PublicKey()

	if _, err := c.GetIssuer(context.Background(), id); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("missing issuer: err = %v, want ErrNotFound", err)
	}

	f.putIssuer(t, c, id, pub, auth, true)
	rec, err := c.GetIssuer(context.Background(), id)
	if err != nil || !rec.Active || !pub.Equal(rec.SigningKey) {
		t.Fatalf("GetIssuer = %+v, %v", rec, err)
	}
}

func TestGetIssuerRejectsAccountForAnotherID(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	asked, other := registry.IssuerID("asked"), registry.IssuerID("other")
	pub, _, _ := ed25519.GenerateKey(nil)
	addr, _ := c.addrs.issuer(asked)
	// The account at the asked-for address claims to be a different issuer.
	f.put(addr, testProgram, issuerData(other, pub, solana.NewWallet().PublicKey(), true, 1))

	if _, err := c.GetIssuer(context.Background(), asked); !errors.Is(err, ErrInvalidAccount) {
		t.Fatalf("err = %v, want ErrInvalidAccount", err)
	}
}

func TestReadRetriesTransientErrorsThenSucceeds(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	id := registry.IssuerID("iss")
	pub, _, _ := ed25519.GenerateKey(nil)
	f.putIssuer(t, c, id, pub, solana.NewWallet().PublicKey(), true)
	f.accountErrs = []error{errors.New("connection reset"), errors.New("503")}

	if _, err := c.GetIssuer(context.Background(), id); err != nil {
		t.Fatalf("err = %v, want success after retries", err)
	}
}

func TestReadFailsClosedWhenRPCStaysDown(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	f.accountErrs = []error{errors.New("down"), errors.New("down"), errors.New("down")}

	_, err := c.GetIssuer(context.Background(), registry.IssuerID("iss"))
	if !errors.Is(err, registry.ErrUnavailable) || errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v, want registry.ErrUnavailable (and not registry.ErrNotFound)", err)
	}
}

func TestRegisterIssuerSendsAndConfirms(t *testing.T) {
	f := newFakeRPC()
	c, registryKey, _ := testClient(f)
	id := registry.IssuerID("iss")
	pub, _, _ := ed25519.GenerateKey(nil)
	auth := solana.NewWallet().PublicKey()

	res, err := c.RegisterIssuer(context.Background(), id, pub, auth)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || len(f.sent) != 1 {
		t.Fatalf("Changed=%v sent=%d, want a single transaction", res.Changed, len(f.sent))
	}
	tx := f.sent[0]
	if payer := tx.Message.AccountKeys[0]; payer != registryKey.PublicKey() {
		t.Fatalf("payer = %s, want the registry authority", payer)
	}
}

func TestRegisterIssuerIsIdempotent(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	id := registry.IssuerID("iss")
	pub, _, _ := ed25519.GenerateKey(nil)
	auth := solana.NewWallet().PublicKey()
	f.putIssuer(t, c, id, pub, auth, true)

	res, err := c.RegisterIssuer(context.Background(), id, pub, auth)
	if err != nil || res.Changed || len(f.sent) != 0 {
		t.Fatalf("identical repeat: res=%+v err=%v sent=%d, want a no-op", res, err, len(f.sent))
	}

	otherKey, _, _ := ed25519.GenerateKey(nil)
	if _, err := c.RegisterIssuer(context.Background(), id, otherKey, auth); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("different key: err = %v, want ErrConflict", err)
	}
	if len(f.sent) != 0 {
		t.Fatal("a conflicting request must not send a transaction")
	}
}

func TestConcurrentCreationCountsAsSuccess(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	id := registry.IssuerID("iss")
	pub, _, _ := ed25519.GenerateKey(nil)
	auth := solana.NewWallet().PublicKey()
	// Our transaction is rejected ("already in use") because another request
	// created the identical record first.
	f.sendErrs = []error{&jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed: custom program error: 0x0"}}
	reads := 0
	// First read: absent. After the failed send: present.
	c.rpc = &readHook{fakeRPC: f, onRead: func() {
		reads++
		if reads == 2 {
			f.putIssuer(t, c, id, pub, auth, true)
		}
	}}

	res, err := c.RegisterIssuer(context.Background(), id, pub, auth)
	if err != nil || res.Changed {
		t.Fatalf("res=%+v err=%v, want idempotent success", res, err)
	}
}

// readHook runs a callback before each account read, to simulate state
// changing underneath the client.
type readHook struct {
	*fakeRPC
	onRead func()
}

func (h *readHook) GetAccountInfoWithOpts(ctx context.Context, a solana.PublicKey, o *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	h.onRead()
	return h.fakeRPC.GetAccountInfoWithOpts(ctx, a, o)
}

func TestPreflightRejectionIsReported(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	f.sendErrs = []error{&jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed: custom program error: 0x1770"}}

	pub, _, _ := ed25519.GenerateKey(nil)
	_, err := c.RegisterIssuer(context.Background(), registry.IssuerID("iss"), pub, solana.NewWallet().PublicKey())
	if !errors.Is(err, ErrTxRejected) {
		t.Fatalf("err = %v, want ErrTxRejected", err)
	}
	if len(f.sent) != 0 {
		t.Fatal("a rejected transaction must not be retried")
	}
}

func TestOnChainFailureIsReported(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	f.status = &rpc.SignatureStatusesResult{Err: map[string]any{"InstructionError": []any{0, "Custom"}}}

	pub, _, _ := ed25519.GenerateKey(nil)
	_, err := c.RegisterIssuer(context.Background(), registry.IssuerID("iss"), pub, solana.NewWallet().PublicKey())
	if !errors.Is(err, ErrTxRejected) {
		t.Fatalf("err = %v, want ErrTxRejected", err)
	}
}

func TestSendRetriesTransientErrors(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	f.sendErrs = []error{errors.New("timeout"), errors.New("503"), nil}

	pub, _, _ := ed25519.GenerateKey(nil)
	res, err := c.RegisterIssuer(context.Background(), registry.IssuerID("iss"), pub, solana.NewWallet().PublicKey())
	if err != nil || !res.Changed {
		t.Fatalf("res=%+v err=%v, want success after retries", res, err)
	}
}

func TestUnconfirmedTransactionIsUncertain(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	f.status = nil // never becomes visible
	c.sleep = func(context.Context, time.Duration) error { return context.DeadlineExceeded }

	pub, _, _ := ed25519.GenerateKey(nil)
	res, err := c.RegisterIssuer(context.Background(), registry.IssuerID("iss"), pub, solana.NewWallet().PublicKey())
	if !errors.Is(err, ErrTxUncertain) {
		t.Fatalf("err = %v, want ErrTxUncertain", err)
	}
	if res.Changed || res.Reference == "" {
		t.Fatalf("res = %+v: must not report success but must carry the signature", res)
	}
}

func TestExpiredBlockhashIsReportedAsExpired(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	f.status = nil
	f.height = f.lastValid + 1

	pub, _, _ := ed25519.GenerateKey(nil)
	_, err := c.RegisterIssuer(context.Background(), registry.IssuerID("iss"), pub, solana.NewWallet().PublicKey())
	if !errors.Is(err, ErrTxExpired) {
		t.Fatalf("err = %v, want ErrTxExpired", err)
	}
}

func TestSignerRoles(t *testing.T) {
	f := newFakeRPC()
	c := newClient(f, options{ProgramID: testProgram})
	pub, _, _ := ed25519.GenerateKey(nil)

	if _, err := c.RegisterIssuer(context.Background(), registry.IssuerID("i"), pub, solana.NewWallet().PublicKey()); !errors.Is(err, ErrSignerMissing) {
		t.Errorf("RegisterIssuer without registry key: err = %v", err)
	}
	if _, err := c.RegisterCredential(context.Background(), registry.IssuerID("i"), registry.CredentialRef("c"), time.Now().Add(time.Hour)); !errors.Is(err, ErrSignerMissing) {
		t.Errorf("RegisterCredential without issuer key: err = %v", err)
	}
}

func TestRegisterCredentialIdempotentAndConflict(t *testing.T) {
	f := newFakeRPC()
	c, _, issuer := testClient(f)
	iss, ref := registry.IssuerID("iss"), registry.CredentialRef("jti")
	exp := time.Unix(1900000000, 0)

	res, err := c.RegisterCredential(context.Background(), iss, ref, exp)
	if err != nil || !res.Changed {
		t.Fatalf("first registration: res=%+v err=%v", res, err)
	}
	if payer := f.sent[0].Message.AccountKeys[0]; payer != issuer.PublicKey() {
		t.Fatalf("payer = %s, want the issuer authority", payer)
	}

	f.putCredential(t, c, ref, iss, 0, exp.Unix())
	if res, err := c.RegisterCredential(context.Background(), iss, ref, exp); err != nil || res.Changed {
		t.Fatalf("identical repeat: res=%+v err=%v, want no-op", res, err)
	}
	if _, err := c.RegisterCredential(context.Background(), iss, ref, exp.Add(time.Hour)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("different expiry: err = %v, want ErrConflict", err)
	}
}

func TestRevokeCredential(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	iss, ref := registry.IssuerID("iss"), registry.CredentialRef("jti")

	if _, err := c.RevokeCredential(context.Background(), iss, ref); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("unregistered credential: err = %v, want ErrNotFound", err)
	}
	if len(f.sent) != 0 {
		t.Fatal("revoking an unknown credential must not send a transaction")
	}

	f.putCredential(t, c, ref, iss, 0, 1900000000)
	res, err := c.RevokeCredential(context.Background(), iss, ref)
	if err != nil || !res.Changed {
		t.Fatalf("revoke: res=%+v err=%v", res, err)
	}

	f.putCredential(t, c, ref, iss, 1, 1900000000)
	if res, err := c.RevokeCredential(context.Background(), iss, ref); err != nil || res.Changed {
		t.Fatalf("revoke again: res=%+v err=%v, want no-op", res, err)
	}
}

func TestSetIssuerStatusNoOpAndUnknown(t *testing.T) {
	f := newFakeRPC()
	c, _, _ := testClient(f)
	id := registry.IssuerID("iss")
	pub, _, _ := ed25519.GenerateKey(nil)

	if _, err := c.SetIssuerStatus(context.Background(), id, false); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("unknown issuer: err = %v, want ErrNotFound", err)
	}
	f.putIssuer(t, c, id, pub, solana.NewWallet().PublicKey(), true)
	if res, err := c.SetIssuerStatus(context.Background(), id, true); err != nil || res.Changed {
		t.Fatalf("already active: res=%+v err=%v, want no-op", res, err)
	}
	if res, err := c.SetIssuerStatus(context.Background(), id, false); err != nil || !res.Changed {
		t.Fatalf("suspend: res=%+v err=%v", res, err)
	}
}
