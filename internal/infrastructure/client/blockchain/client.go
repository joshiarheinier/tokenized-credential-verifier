package blockchain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/registry"
)

// rpcAPI is the subset of the SDK's RPC client the adapter uses, so tests can
// substitute a fake.
type rpcAPI interface {
	GetAccountInfoWithOpts(ctx context.Context, account solana.PublicKey, opts *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error)
	GetLatestBlockhashWithOpts(ctx context.Context, opts *rpc.GetLatestBlockhashOpts) (*rpc.GetLatestBlockhashResult, error)
	SendTransactionWithOpts(ctx context.Context, tx *solana.Transaction, opts rpc.TransactionOpts) (solana.Signature, error)
	GetSignatureStatuses(ctx context.Context, searchTransactionHistory bool, sigs ...solana.Signature) (*rpc.GetSignatureStatusesResult, error)
	GetBlockHeight(ctx context.Context, commitment rpc.CommitmentType) (uint64, error)
}

// options configures a Client.
type options struct {
	ProgramID solana.PublicKey
	// Commitment is used for reads, preflight and confirmation. Default: confirmed.
	Commitment rpc.CommitmentType
	// RegistryAuthority signs registry administration (initialize, register
	// issuer, change issuer status). Optional for read-only use.
	RegistryAuthority *solana.PrivateKey
	// IssuerAuthority signs credential registration and revocation for the
	// issuer. Optional for read-only use.
	IssuerAuthority *solana.PrivateKey
	// Attempts bounds tries for transient RPC failures. Default: 3.
	Attempts int
	// Backoff is the base delay between attempts, doubled each time. Default: 200ms.
	Backoff time.Duration
	// RequestTimeout bounds a single RPC call. Default: 10s.
	RequestTimeout time.Duration
	// TxTimeout bounds waiting for a submitted transaction to confirm. Default: 30s.
	TxTimeout time.Duration
	// PollInterval is the delay between confirmation checks. Default: 400ms.
	PollInterval time.Duration
}

// Client reads and writes the on-chain registry.
type Client struct {
	rpc   rpcAPI
	addrs addresses
	opts  options
	sleep func(ctx context.Context, d time.Duration) error
}

// Config is the deployment configuration of a Client. Only RPCURL and
// ProgramID are required; everything else has a default.
type Config struct {
	RPCURL    string
	ProgramID string
	// Commitment is "confirmed" (default) or "finalized". It is used for
	// reads, preflight and confirming writes.
	Commitment string
	// Keypair files in solana-keygen JSON format. Either may be empty for a
	// process that does not need that role. They are secrets: their contents
	// are never logged or included in errors.
	//
	// The registry authority signs registry administration (initialize,
	// register issuer, change issuer status); the issuer authority signs
	// credential registration and revocation.
	RegistryAuthorityKeypair string
	IssuerAuthorityKeypair   string
	// RequestTimeout bounds a single RPC call. Default: 10s.
	RequestTimeout time.Duration
	// TxTimeout bounds waiting for a submitted transaction to confirm. Default: 30s.
	TxTimeout time.Duration
	// Attempts bounds tries for transient RPC failures. Default: 3.
	Attempts int
	// Backoff is the base delay between attempts, doubled each time. Default: 200ms.
	Backoff time.Duration
	// PollInterval is the delay between confirmation checks. Default: 400ms.
	PollInterval time.Duration
}

// NewClient returns a Client for the registry program described by cfg.
func NewClient(cfg Config) (*Client, error) {
	program, err := solana.PublicKeyFromBase58(cfg.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("blockchain: invalid program id %q: %w", cfg.ProgramID, err)
	}
	opts := options{
		ProgramID:      program,
		RequestTimeout: cfg.RequestTimeout,
		TxTimeout:      cfg.TxTimeout,
		Attempts:       cfg.Attempts,
		Backoff:        cfg.Backoff,
		PollInterval:   cfg.PollInterval,
	}
	switch cfg.Commitment {
	case "", "confirmed":
		opts.Commitment = rpc.CommitmentConfirmed
	case "finalized":
		opts.Commitment = rpc.CommitmentFinalized
	default:
		return nil, fmt.Errorf("blockchain: unsupported commitment %q", cfg.Commitment)
	}
	if opts.RegistryAuthority, err = loadKeypair("registry authority", cfg.RegistryAuthorityKeypair); err != nil {
		return nil, err
	}
	if opts.IssuerAuthority, err = loadKeypair("issuer authority", cfg.IssuerAuthorityKeypair); err != nil {
		return nil, err
	}
	return newClient(rpc.New(cfg.RPCURL), opts), nil
}

func newClient(api rpcAPI, opts options) *Client {
	if opts.Commitment == "" {
		opts.Commitment = rpc.CommitmentConfirmed
	}
	if opts.Attempts <= 0 {
		opts.Attempts = 3
	}
	if opts.Backoff <= 0 {
		opts.Backoff = 200 * time.Millisecond
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 10 * time.Second
	}
	if opts.TxTimeout <= 0 {
		opts.TxTimeout = 30 * time.Second
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 400 * time.Millisecond
	}
	return &Client{rpc: api, addrs: addresses{program: opts.ProgramID}, opts: opts, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- Reads -----------------------------------------------------------------

// GetRegistry returns the registry configuration, or registry.ErrNotFound if the
// registry has not been initialized.
func (c *Client) GetRegistry(ctx context.Context) (RegistryConfig, error) {
	addr, err := c.addrs.registryConfig()
	if err != nil {
		return RegistryConfig{}, err
	}
	acct, err := c.readAccount(ctx, addr)
	if err != nil {
		return RegistryConfig{}, err
	}
	return decodeRegistryConfig(c.opts.ProgramID, acct.Owner, acct.Data.GetBinary())
}

// GetIssuer returns the issuer record, or registry.ErrNotFound if it is not registered.
func (c *Client) GetIssuer(ctx context.Context, id [32]byte) (registry.IssuerRecord, error) {
	addr, err := c.addrs.issuer(id)
	if err != nil {
		return registry.IssuerRecord{}, err
	}
	acct, err := c.readAccount(ctx, addr)
	if err != nil {
		return registry.IssuerRecord{}, err
	}
	rec, err := decodeIssuerRecord(c.opts.ProgramID, acct.Owner, acct.Data.GetBinary())
	if err != nil {
		return registry.IssuerRecord{}, err
	}
	if rec.IssuerID != id {
		return registry.IssuerRecord{}, fmt.Errorf("issuer record: %w: id mismatch", ErrInvalidAccount)
	}
	return rec, nil
}

// GetCredentialStatus returns the on-chain status of a credential reference,
// or registry.ErrNotFound if it was never registered.
func (c *Client) GetCredentialStatus(ctx context.Context, ref [32]byte) (registry.CredentialStatus, error) {
	addr, err := c.addrs.credential(ref)
	if err != nil {
		return registry.CredentialStatus{}, err
	}
	acct, err := c.readAccount(ctx, addr)
	if err != nil {
		return registry.CredentialStatus{}, err
	}
	st, err := decodeCredentialStatus(c.opts.ProgramID, acct.Owner, acct.Data.GetBinary())
	if err != nil {
		return registry.CredentialStatus{}, err
	}
	if st.Ref != ref {
		return registry.CredentialStatus{}, fmt.Errorf("credential status: %w: ref mismatch", ErrInvalidAccount)
	}
	return st, nil
}

type account struct {
	Owner solana.PublicKey
	Data  *rpc.DataBytesOrJSON
}

func (c *Client) readAccount(ctx context.Context, addr solana.PublicKey) (account, error) {
	var out account
	err := c.retry(ctx, func(ctx context.Context) error {
		res, err := c.rpc.GetAccountInfoWithOpts(ctx, addr, &rpc.GetAccountInfoOpts{
			Encoding:   solana.EncodingBase64,
			Commitment: c.opts.Commitment,
		})
		if err != nil {
			return err
		}
		if res == nil || res.Value == nil || res.Value.Data == nil {
			return rpc.ErrNotFound
		}
		out = account{Owner: res.Value.Owner, Data: res.Value.Data}
		return nil
	})
	if errors.Is(err, rpc.ErrNotFound) {
		return account{}, registry.ErrNotFound
	}
	if err != nil {
		return account{}, fmt.Errorf("%w: %v", registry.ErrUnavailable, err)
	}
	return out, nil
}

// --- Writes ----------------------------------------------------------------

// InitializeRegistry creates the registry configuration with the registry
// authority as administrator. The authority key must also be the program's
// upgrade authority. It is a no-op if the registry already exists with this
// authority.
func (c *Client) InitializeRegistry(ctx context.Context) (registry.WriteResult, error) {
	signer, err := c.registrySigner()
	if err != nil {
		return registry.WriteResult{}, err
	}
	matches := func() (bool, error) {
		cfg, err := c.GetRegistry(ctx)
		if err != nil {
			return false, err
		}
		if cfg.Authority != signer.PublicKey() {
			return false, fmt.Errorf("%w: registry already initialized with a different authority", registry.ErrConflict)
		}
		return true, nil
	}
	ix, err := c.addrs.initializeRegistryIx(signer.PublicKey())
	if err != nil {
		return registry.WriteResult{}, err
	}
	return c.ensure(ctx, signer, matches, ix)
}

// RegisterIssuer registers a trusted issuer. It is a no-op if an identical
// record exists, and returns registry.ErrConflict if a different one does.
func (c *Client) RegisterIssuer(ctx context.Context, id [32]byte, signingKey []byte, authority solana.PublicKey) (registry.WriteResult, error) {
	signer, err := c.registrySigner()
	if err != nil {
		return registry.WriteResult{}, err
	}
	want := registry.IssuerRecord{IssuerID: id, SigningKey: signingKey, Authority: authority}
	matches := func() (bool, error) {
		got, err := c.GetIssuer(ctx, id)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(got.SigningKey, want.SigningKey) || got.Authority != want.Authority {
			return false, fmt.Errorf("%w: issuer already registered with different keys", registry.ErrConflict)
		}
		return true, nil
	}
	ix, err := c.addrs.registerIssuerIx(signer.PublicKey(), want)
	if err != nil {
		return registry.WriteResult{}, err
	}
	return c.ensure(ctx, signer, matches, ix)
}

// SetIssuerStatus activates or suspends an issuer. It is a no-op if the issuer
// already has the requested status, and returns registry.ErrNotFound if it is unknown.
func (c *Client) SetIssuerStatus(ctx context.Context, id [32]byte, active bool) (registry.WriteResult, error) {
	signer, err := c.registrySigner()
	if err != nil {
		return registry.WriteResult{}, err
	}
	matches := func() (bool, error) {
		got, err := c.GetIssuer(ctx, id)
		if err != nil {
			return false, err
		}
		return got.Active == active, nil
	}
	ix, err := c.addrs.setIssuerStatusIx(signer.PublicKey(), id, active)
	if err != nil {
		return registry.WriteResult{}, err
	}
	return c.ensureExisting(ctx, signer, matches, ix)
}

// RegisterCredential records a credential reference as active. It is a no-op
// if an identical record exists, and returns registry.ErrConflict if a different one does.
func (c *Client) RegisterCredential(ctx context.Context, issuerID, ref [32]byte, expiresAt time.Time) (registry.WriteResult, error) {
	signer, err := c.issuerSigner()
	if err != nil {
		return registry.WriteResult{}, err
	}
	matches := func() (bool, error) {
		got, err := c.GetCredentialStatus(ctx, ref)
		if err != nil {
			return false, err
		}
		if got.IssuerID != issuerID || !got.ExpiresAt.Equal(expiresAt.Truncate(time.Second)) {
			return false, fmt.Errorf("%w: credential reference already registered with different data", registry.ErrConflict)
		}
		return true, nil
	}
	ix, err := c.addrs.registerCredentialIx(signer.PublicKey(), issuerID, ref, expiresAt)
	if err != nil {
		return registry.WriteResult{}, err
	}
	return c.ensure(ctx, signer, matches, ix)
}

// RevokeCredential revokes a registered credential. It is a no-op if it is
// already revoked, and returns registry.ErrNotFound if it was never registered.
func (c *Client) RevokeCredential(ctx context.Context, issuerID, ref [32]byte) (registry.WriteResult, error) {
	signer, err := c.issuerSigner()
	if err != nil {
		return registry.WriteResult{}, err
	}
	matches := func() (bool, error) {
		got, err := c.GetCredentialStatus(ctx, ref)
		if err != nil {
			return false, err
		}
		return got.State == registry.CredentialRevoked, nil
	}
	ix, err := c.addrs.revokeCredentialIx(signer.PublicKey(), issuerID, ref)
	if err != nil {
		return registry.WriteResult{}, err
	}
	return c.ensureExisting(ctx, signer, matches, ix)
}

// IssuerAuthority returns the public key of the configured issuer authority.
func (c *Client) IssuerAuthority() (solana.PublicKey, error) {
	k, err := c.issuerSigner()
	if err != nil {
		return solana.PublicKey{}, err
	}
	return k.PublicKey(), nil
}

func (c *Client) registrySigner() (solana.PrivateKey, error) {
	if c.opts.RegistryAuthority == nil {
		return nil, fmt.Errorf("%w: registry authority", ErrSignerMissing)
	}
	return *c.opts.RegistryAuthority, nil
}

func (c *Client) issuerSigner() (solana.PrivateKey, error) {
	if c.opts.IssuerAuthority == nil {
		return nil, fmt.Errorf("%w: issuer authority", ErrSignerMissing)
	}
	return *c.opts.IssuerAuthority, nil
}

// ensure makes a create-style change idempotent. matches reports whether the
// chain already holds the desired state: (true, nil) means nothing to do,
// registry.ErrNotFound means it must be created, and any other error aborts.
func (c *Client) ensure(ctx context.Context, signer solana.PrivateKey, matches func() (bool, error), ix solana.Instruction) (registry.WriteResult, error) {
	ok, err := matches()
	switch {
	case err == nil && ok:
		return registry.WriteResult{}, nil
	case err != nil && !errors.Is(err, registry.ErrNotFound):
		return registry.WriteResult{}, err
	}

	sig, err := c.submit(ctx, signer, ix)
	if err != nil {
		// A concurrent request may have created the same record between our
		// read and our transaction. If the chain now matches, that is success.
		if errors.Is(err, ErrTxRejected) {
			if ok, mErr := matches(); mErr == nil && ok {
				return registry.WriteResult{}, nil
			}
		}
		return registry.WriteResult{Reference: refOf(err)}, err
	}
	return registry.WriteResult{Reference: sig.String(), Changed: true}, nil
}

// ensureExisting is ensure for state changes on a record that must already
// exist: registry.ErrNotFound is returned to the caller rather than triggering a send.
func (c *Client) ensureExisting(ctx context.Context, signer solana.PrivateKey, matches func() (bool, error), ix solana.Instruction) (registry.WriteResult, error) {
	ok, err := matches()
	if err != nil {
		return registry.WriteResult{}, err
	}
	if ok {
		return registry.WriteResult{}, nil
	}
	sig, err := c.submit(ctx, signer, ix)
	if err != nil {
		if errors.Is(err, ErrTxRejected) {
			if ok, mErr := matches(); mErr == nil && ok {
				return registry.WriteResult{}, nil
			}
		}
		return registry.WriteResult{Reference: refOf(err)}, err
	}
	return registry.WriteResult{Reference: sig.String(), Changed: true}, nil
}

// refOf returns the transaction signature carried by a failed write's error, as
// the Reference of a registry.WriteResult, or "" if there is none.
func refOf(err error) string {
	var txErr *TxError
	if errors.As(err, &txErr) && !txErr.Signature.IsZero() {
		return txErr.Signature.String()
	}
	return ""
}

// submit signs, sends and confirms a single-instruction transaction. It
// returns nil only once the transaction has reached the configured commitment
// without error.
func (c *Client) submit(ctx context.Context, signer solana.PrivateKey, ix solana.Instruction) (solana.Signature, error) {
	var bh *rpc.LatestBlockhashResult
	err := c.retry(ctx, func(ctx context.Context) error {
		res, err := c.rpc.GetLatestBlockhashWithOpts(ctx, &rpc.GetLatestBlockhashOpts{Commitment: c.opts.Commitment})
		if err != nil {
			return err
		}
		if res == nil || res.Value == nil {
			return errors.New("empty blockhash response")
		}
		bh = res.Value
		return nil
	})
	if err != nil {
		return solana.Signature{}, fmt.Errorf("%w: latest blockhash: %v", registry.ErrUnavailable, err)
	}

	tx, err := solana.NewTransaction([]solana.Instruction{ix}, bh.Blockhash, solana.TransactionPayer(signer.PublicKey()))
	if err != nil {
		return solana.Signature{}, fmt.Errorf("build transaction: %w", err)
	}
	if _, err := tx.Sign(func(pk solana.PublicKey) *solana.PrivateKey {
		if pk == signer.PublicKey() {
			return &signer
		}
		return nil
	}); err != nil {
		return solana.Signature{}, fmt.Errorf("sign transaction: %w", err)
	}

	sig, err := c.send(ctx, tx)
	if err != nil {
		return sig, err
	}
	return sig, c.confirm(ctx, sig, bh.LastValidBlockHeight)
}

// send submits the transaction, retrying transient failures. Resending the
// same signed transaction is safe: it has one signature and can land once.
func (c *Client) send(ctx context.Context, tx *solana.Transaction) (solana.Signature, error) {
	var sig solana.Signature
	err := c.retry(ctx, func(ctx context.Context) error {
		s, err := c.rpc.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
			PreflightCommitment: c.opts.Commitment,
		})
		if err == nil {
			sig = s
			return nil
		}
		var rpcErr *jsonrpc.RPCError
		if errors.As(err, &rpcErr) {
			switch {
			case strings.Contains(rpcErr.Message, "already been processed"):
				sig = tx.Signatures[0]
				return nil
			case rpcErr.Code == -32002 && !strings.Contains(rpcErr.Message, "Blockhash not found"):
				// Preflight simulation failed: the program rejected it.
				return permanent{&TxError{Kind: ErrTxRejected, Signature: tx.Signatures[0], Detail: rpcDetail(rpcErr)}}
			}
		}
		return err
	})
	if err != nil {
		var txErr *TxError
		if errors.As(err, &txErr) {
			return txErr.Signature, txErr
		}
		return tx.Signatures[0], fmt.Errorf("%w: send: %v", registry.ErrUnavailable, err)
	}
	return sig, nil
}

func rpcDetail(e *jsonrpc.RPCError) string {
	d := fmt.Sprintf("%s %v", e.Message, e.Data)
	if len(d) > 512 {
		d = d[:512] + "..."
	}
	return d
}

// confirm polls until the signature reaches the configured commitment, the
// transaction fails, the blockhash expires, or TxTimeout elapses.
func (c *Client) confirm(ctx context.Context, sig solana.Signature, lastValidBlockHeight uint64) error {
	ctx, cancel := context.WithTimeout(ctx, c.opts.TxTimeout)
	defer cancel()

	uncertain := func(why string) error {
		return &TxError{Kind: ErrTxUncertain, Signature: sig, Detail: why}
	}
	for {
		confirmed, err := c.checkStatus(ctx, sig)
		switch {
		case err != nil:
			return err
		case confirmed:
			return nil
		}

		// Not seen yet. If the blockhash has expired the transaction can no
		// longer land; check once more to close the race, then give up.
		if h, err := c.blockHeight(ctx); err == nil && h > lastValidBlockHeight {
			confirmed, err := c.checkStatus(ctx, sig)
			switch {
			case err != nil:
				return err
			case confirmed:
				return nil
			}
			return &TxError{Kind: ErrTxExpired, Signature: sig, Detail: "blockhash expired before confirmation"}
		}

		if err := c.sleep(ctx, c.opts.PollInterval); err != nil {
			return uncertain("timed out waiting for confirmation")
		}
	}
}

// checkStatus reports whether the signature has reached the configured
// commitment. Transient RPC errors count as "not yet"; an on-chain error is
// returned as ErrTxRejected.
func (c *Client) checkStatus(ctx context.Context, sig solana.Signature) (bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.opts.RequestTimeout)
	defer cancel()
	res, err := c.rpc.GetSignatureStatuses(callCtx, true, sig)
	if err != nil || res == nil || len(res.Value) == 0 || res.Value[0] == nil {
		return false, nil
	}
	st := res.Value[0]
	if st.Err != nil {
		return false, &TxError{Kind: ErrTxRejected, Signature: sig, Detail: fmt.Sprint(st.Err)}
	}
	return reached(st.ConfirmationStatus, c.opts.Commitment), nil
}

func reached(got rpc.ConfirmationStatusType, want rpc.CommitmentType) bool {
	switch want {
	case rpc.CommitmentFinalized:
		return got == rpc.ConfirmationStatusFinalized
	case rpc.CommitmentConfirmed:
		return got == rpc.ConfirmationStatusConfirmed || got == rpc.ConfirmationStatusFinalized
	default:
		return got != ""
	}
}

func (c *Client) blockHeight(ctx context.Context) (uint64, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.opts.RequestTimeout)
	defer cancel()
	return c.rpc.GetBlockHeight(callCtx, c.opts.Commitment)
}

// permanent marks an error that must not be retried.
type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// retry runs fn up to Attempts times with exponential backoff, bounding each
// call by RequestTimeout. It stops early on rpc.ErrNotFound, permanent errors
// and context cancellation.
func (c *Client) retry(ctx context.Context, fn func(context.Context) error) error {
	delay := c.opts.Backoff
	var err error
	for attempt := 1; ; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, c.opts.RequestTimeout)
		err = fn(callCtx)
		cancel()
		if err == nil || errors.Is(err, rpc.ErrNotFound) {
			return err
		}
		var p permanent
		if errors.As(err, &p) {
			return err
		}
		if ctx.Err() != nil || attempt >= c.opts.Attempts {
			return err
		}
		if sleepErr := c.sleep(ctx, delay); sleepErr != nil {
			return err
		}
		delay *= 2
	}
}
