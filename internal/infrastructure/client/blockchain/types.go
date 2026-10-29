// Package blockchain implements the trust registry (internal/domain/registry)
// on top of the Solana registry program in contracts/credential-registry. It is
// the only package that imports the Solana SDK. Client returns the domain's
// registry types and reports the domain's errors (registry.ErrNotFound,
// registry.ErrUnavailable, registry.ErrConflict), so the application layer can
// depend on the domain alone and define its own small interfaces over Client.
//
// All data read from an RPC node is treated as untrusted: accounts are checked
// for the expected owner, discriminator and exact size before use, and any
// failure to establish state is reported as an error, never as a default.
package blockchain

import (
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Errors specific to this adapter. Use errors.Is to classify them. Errors every
// registry implementation shares are defined by the domain (registry.ErrNotFound
// and friends).
var (
	// ErrInvalidAccount means an account exists but is not a valid record of
	// this program (wrong owner, discriminator, size or field values).
	ErrInvalidAccount = errors.New("blockchain: invalid account")
	// ErrSignerMissing means no key is configured for the required role.
	ErrSignerMissing = errors.New("blockchain: signer not configured")
	// ErrTxRejected means the transaction was rejected or failed on chain. It
	// definitely had no effect.
	ErrTxRejected = errors.New("blockchain: transaction rejected")
	// ErrTxUncertain means the transaction was submitted but its outcome could
	// not be determined. It may still land.
	ErrTxUncertain = errors.New("blockchain: transaction outcome uncertain")
	// ErrTxExpired means the transaction's blockhash expired before it was
	// confirmed, so it can no longer land and is safe to retry.
	ErrTxExpired = errors.New("blockchain: transaction expired")
)

// TxError carries the signature and detail of a failed or unresolved
// transaction. Its Kind is one of ErrTxRejected, ErrTxUncertain or ErrTxExpired.
type TxError struct {
	Kind      error
	Signature solana.Signature
	Detail    string
}

func (e *TxError) Error() string {
	return fmt.Sprintf("%v (signature %s): %s", e.Kind, e.Signature, e.Detail)
}

func (e *TxError) Is(target error) bool { return target == e.Kind }

// RegistryConfig mirrors the on-chain RegistryConfig account. It is specific to
// the Solana program's administration and is not part of the domain model.
type RegistryConfig struct {
	Authority solana.PublicKey
	Paused    bool
	Version   uint8
}
