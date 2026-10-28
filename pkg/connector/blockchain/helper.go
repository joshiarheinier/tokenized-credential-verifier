package blockchain

import (
	"crypto/sha256"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// IssuerID maps a credential issuer identifier (the "iss" claim) to the
// 32-byte on-chain issuer id. Issuer identifiers are public, so a plain
// domain-separated hash is sufficient.
func IssuerID(issuer string) [32]byte {
	return sha256.Sum256([]byte("kyc-registry/issuer/v1\x00" + issuer))
}

// CredentialRef maps a credential's random id (the "jti" claim) to the opaque
// 32-byte on-chain credential reference. The credential id is an unguessable
// random value, so the reference reveals nothing about the subject and cannot
// be linked to a credential by anyone who does not hold it.
func CredentialRef(credentialID string) [32]byte {
	return sha256.Sum256([]byte("kyc-registry/credential/v1\x00" + credentialID))
}

// LoadKeypair reads a solana-keygen JSON keypair file.
func LoadKeypair(path string) (solana.PrivateKey, error) {
	key, err := solana.PrivateKeyFromSolanaKeygenFile(path)
	if err != nil {
		// Do not wrap err: parse errors can echo file contents.
		return nil, fmt.Errorf("blockchain: cannot read keypair file %q", path)
	}
	return key, nil
}

// loadKeypair loads an optional keypair; an empty path means "not configured".
func loadKeypair(role, path string) (*solana.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	key, err := LoadKeypair(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", role, err)
	}
	return &key, nil
}
