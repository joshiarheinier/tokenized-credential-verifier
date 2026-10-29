package blockchain

import (
	"fmt"

	"github.com/gagliardetto/solana-go"
)

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
