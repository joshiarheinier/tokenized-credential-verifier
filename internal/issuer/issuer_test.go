package issuer

import (
	"strings"
	"testing"
)

func TestSeedRoundTripIsDeterministic(t *testing.T) {
	seed, err := GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New("did:example:a", seed)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := New("did:example:a", seed)
	if !a.Signer.PublicKey().Equal(b.Signer.PublicKey()) {
		t.Error("same seed produced different keys")
	}
	other, _ := GenerateSeed()
	c, _ := New("did:example:a", other)
	if a.Signer.PublicKey().Equal(c.Signer.PublicKey()) {
		t.Error("different seeds produced the same key")
	}
}

func TestNewRejectsBadSeedWithoutLeakingIt(t *testing.T) {
	for _, seed := range []string{"", "short", "!!!not-base64!!!"} {
		_, err := New("did:example:a", seed)
		if err == nil {
			t.Errorf("seed %q accepted", seed)
			continue
		}
		if seed != "" && strings.Contains(err.Error(), seed) {
			t.Errorf("error leaks seed: %v", err)
		}
	}
}
