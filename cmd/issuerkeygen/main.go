// Command issuerkeygen generates a dedicated Ed25519 credential-signing seed
// for the issuer. Put the output in ISSUER_SIGNING_KEY_SEED (a git-ignored
// .env for development, a secret manager otherwise). This key is separate from
// any Solana transaction-signing key.
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/joshiarheinier/tokenized-credential-verifier/internal/credential"
	"github.com/joshiarheinier/tokenized-credential-verifier/internal/domain/issuer"
)

func main() {
	seed, err := issuer.GenerateSeed()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	iss, err := issuer.New("generated", seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pub := iss.Signer.PublicKey()

	// Only the seed goes to stdout so it can be captured; commentary goes to stderr.
	fmt.Println("ISSUER_SIGNING_KEY_SEED=" + seed)
	fmt.Fprintf(os.Stderr, "public key (base64url): %s\nkey id: %s\nkeep the seed secret and never commit it\n",
		base64.RawURLEncoding.EncodeToString(pub), credential.KeyID(pub))
}
