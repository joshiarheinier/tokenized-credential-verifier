// Package blockchain is the adapter between the application and the Solana
// registry program in contracts/kyc-registry. It is the only package that
// imports the Solana SDK; business logic depends on the small interfaces and
// plain types declared here.
//
// All data read from an RPC node is treated as untrusted: accounts are checked
// for the expected owner, discriminator and exact size before use, and any
// failure to establish state is reported as an error, never as a default.
package blockchain

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/gagliardetto/solana-go"
)

// Errors returned by the adapter. Use errors.Is to classify them.
var (
	// ErrNotFound means the account does not exist on chain.
	ErrNotFound = errors.New("blockchain: account not found")
	// ErrUnavailable means the chain could not be reached or answered
	// unusably. It says nothing about the state of the requested record.
	ErrUnavailable = errors.New("blockchain: chain unavailable")
	// ErrInvalidAccount means an account exists but is not a valid record of
	// this program (wrong owner, discriminator, size or field values).
	ErrInvalidAccount = errors.New("blockchain: invalid account")
	// ErrConflict means a record already exists with different contents than
	// the one requested.
	ErrConflict = errors.New("blockchain: conflicting record exists")
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

// RegistryConfig mirrors the on-chain RegistryConfig account.
type RegistryConfig struct {
	Authority solana.PublicKey
	Paused    bool
	Version   uint8
}

// IssuerRecord mirrors the on-chain IssuerRecord account.
type IssuerRecord struct {
	IssuerID [32]byte
	// SigningKey is the Ed25519 key the issuer signs credentials with.
	SigningKey ed25519.PublicKey
	// Authority is the Solana key that registers and revokes the issuer's
	// credentials.
	Authority solana.PublicKey
	Active    bool
	CreatedAt time.Time
}

// CredentialState is the on-chain status of a credential.
type CredentialState uint8

const (
	CredentialActive  CredentialState = 0
	CredentialRevoked CredentialState = 1
)

// CredentialStatus mirrors the on-chain CredentialStatus account.
type CredentialStatus struct {
	Ref       [32]byte
	IssuerID  [32]byte
	State     CredentialState
	ExpiresAt time.Time
}

// WriteResult reports the outcome of a registry write. Changed is false when
// the chain already held the requested state, in which case no transaction was
// sent and Signature is zero.
type WriteResult struct {
	Signature solana.Signature
	Changed   bool
}
