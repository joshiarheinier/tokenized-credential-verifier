package challenge

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"
)

// ErrHolderBinding means the credential is not bound to whoever signed the
// response: its subject is not a holder id, or the signature does not verify
// under the key in it.
var ErrHolderBinding = errors.New("challenge: holder binding failed")

const (
	messageHeader = "tcv-challenge-response/v1"
	holderPrefix  = "solana:"
	base58Digits  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

// Message returns the text a holder signs to answer c with token. See
// docs/challenge_response_protocol.md, section 5. The wallet builds the same text, and
// the verifier rebuilds it rather than trusting a copy.
func Message(c Challenge, token string) string {
	sum := sha256.Sum256([]byte(token))
	return strings.Join([]string{
		messageHeader,
		"audience: " + c.Audience,
		"challenge: " + c.ID,
		"type: " + c.CredentialType,
		"claims: " + strings.Join(c.Claims, ","),
		"credential: sha256:" + hex.EncodeToString(sum[:]),
		"expires: " + c.ExpiresAt.UTC().Format(time.RFC3339),
	}, "\n")
}

// HolderKey returns the Ed25519 public key named by a holder id: "solana:"
// followed by the base58 form of the 32-byte key, as shown by wallets such as
// Phantom.
func HolderKey(subject string) (ed25519.PublicKey, error) {
	address, ok := strings.CutPrefix(subject, holderPrefix)
	if !ok || address == "" || len(address) > 44 {
		return nil, ErrHolderBinding
	}
	key, err := decodeBase58(address)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, ErrHolderBinding
	}
	return key, nil
}

// HolderID returns the holder id for a public key.
func HolderID(key ed25519.PublicKey) string { return holderPrefix + encodeBase58(key) }

// VerifyHolder checks that signature is the signature, by the holder named in
// subject, over the message for answering c with token. subject must come from a
// credential whose issuer signature has already been verified.
func VerifyHolder(c Challenge, token, subject string, signature []byte) error {
	key, err := HolderKey(subject)
	if err != nil {
		return err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, []byte(Message(c, token)), signature) {
		return ErrHolderBinding
	}
	return nil
}

func decodeBase58(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for _, r := range s {
		i := strings.IndexRune(base58Digits, r)
		if i < 0 {
			return nil, errors.New("not base58")
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(i)))
	}
	zeros := len(s) - len(strings.TrimLeft(s, "1"))
	return append(make([]byte, zeros), n.Bytes()...), nil
}

func encodeBase58(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base, mod := big.NewInt(58), new(big.Int)
	var digits []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		digits = append(digits, base58Digits[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		digits = append(digits, '1')
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}
