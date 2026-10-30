package challenge

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

var expiry = time.Date(2026, 11, 3, 10, 15, 0, 0, time.UTC)

func testChallenge(t *testing.T) Challenge {
	t.Helper()
	c, err := NewChallenge("AAAAAAAAAAAAAAAAAAAAAA", "http://localhost:9090", "KYCStatus", []string{"over_18"}, "http://localhost:9090/callback", expiry)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The signed text is a contract with the wallet's JavaScript: this pins it.
func TestMessageFormatIsPinned(t *testing.T) {
	want := "tcv-challenge-response/v1\n" +
		"audience: http://localhost:9090\n" +
		"challenge: AAAAAAAAAAAAAAAAAAAAAA\n" +
		"type: KYCStatus\n" +
		"claims: over_18\n" +
		"credential: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n" +
		"expires: 2026-11-03T10:15:00Z"
	if got := Message(testChallenge(t), "test"); got != want {
		t.Fatalf("message =\n%s\nwant\n%s", got, want)
	}
}

func TestBase58MatchesKnownSolanaAddresses(t *testing.T) {
	for address, wantHex := range map[string]string{
		"11111111111111111111111111111111":            "0000000000000000000000000000000000000000000000000000000000000000",
		"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9",
	} {
		key, err := HolderKey("solana:" + address)
		if err != nil {
			t.Fatalf("%s: %v", address, err)
		}
		if got := hex.EncodeToString(key); got != wantHex {
			t.Errorf("%s decodes to %s, want %s", address, got, wantHex)
		}
		if got := HolderID(key); got != "solana:"+address {
			t.Errorf("HolderID round trip = %s, want solana:%s", got, address)
		}
	}
}

func TestHolderKeyRejectsWhatIsNotAHolderID(t *testing.T) {
	for _, subject := range []string{
		"", "solana:", "did:example:demo-user", "user-1",
		"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // no prefix
		"solana:0OIl", // characters outside base58
		"solana:4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vig",   // 31 bytes
		"solana:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DAA", // too long
	} {
		if _, err := HolderKey(subject); !errors.Is(err, ErrHolderBinding) {
			t.Errorf("HolderKey(%q) err = %v, want ErrHolderBinding", subject, err)
		}
	}
}

func TestVerifyHolder(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := testChallenge(t)
	sign := func(c Challenge, token string) []byte { return ed25519.Sign(priv, []byte(Message(c, token))) }
	subject := HolderID(pub)

	if err := VerifyHolder(c, "token", subject, sign(c, "token")); err != nil {
		t.Fatalf("a signature by the holder over this response: %v", err)
	}

	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherChallenge := c
	otherChallenge.Audience = "http://localhost:9091"
	for name, tc := range map[string]struct {
		subject string
		token   string
		sig     []byte
	}{
		"credential bound to another key":   {HolderID(other), "token", sign(c, "token")},
		"signature over another credential": {subject, "token", sign(c, "other-token")},
		"signature for another audience":    {subject, "token", sign(otherChallenge, "token")},
		"truncated signature":               {subject, "token", sign(c, "token")[:40]},
		"no signature":                      {subject, "token", nil},
		"subject is not a holder id":        {"user-1", "token", sign(c, "token")},
	} {
		if err := VerifyHolder(c, tc.token, tc.subject, tc.sig); !errors.Is(err, ErrHolderBinding) {
			t.Errorf("%s: err = %v, want ErrHolderBinding", name, err)
		}
	}
}

func TestNewChallengeValidatesAndNormalizes(t *testing.T) {
	c, err := NewChallenge("id", "https://app.example", "Membership", []string{"tier", "active"}, "https://app.example/cb?x=1", expiry)
	if err != nil {
		t.Fatal(err)
	}
	if c.Claims[0] != "active" || c.Claims[1] != "tier" {
		t.Errorf("claims = %v, want sorted", c.Claims)
	}

	bad := map[string]func() error{
		"empty id":               func() error { _, e := NewChallenge("", "https://a.example", "T", []string{"c"}, "", expiry); return e },
		"http for a public host": func() error { _, e := NewChallenge("i", "http://a.example", "T", []string{"c"}, "", expiry); return e },
		"audience with a path": func() error {
			_, e := NewChallenge("i", "https://a.example/x", "T", []string{"c"}, "", expiry)
			return e
		},
		"audience with userinfo": func() error {
			_, e := NewChallenge("i", "https://u@a.example", "T", []string{"c"}, "", expiry)
			return e
		},
		"non-ASCII audience": func() error {
			_, e := NewChallenge("i", "https://äpp.example", "T", []string{"c"}, "", expiry)
			return e
		},
		"bad credential type": func() error {
			_, e := NewChallenge("i", "https://a.example", "has space", []string{"c"}, "", expiry)
			return e
		},
		"no claims": func() error { _, e := NewChallenge("i", "https://a.example", "T", nil, "", expiry); return e },
		"bad claim name": func() error {
			_, e := NewChallenge("i", "https://a.example", "T", []string{"Over 18"}, "", expiry)
			return e
		},
		"duplicate claim": func() error {
			_, e := NewChallenge("i", "https://a.example", "T", []string{"c", "c"}, "", expiry)
			return e
		},
		"callback on another origin": func() error {
			_, e := NewChallenge("i", "https://a.example", "T", []string{"c"}, "https://evil.example/cb", expiry)
			return e
		},
		"callback with a fragment": func() error {
			_, e := NewChallenge("i", "https://a.example", "T", []string{"c"}, "https://a.example/cb#x", expiry)
			return e
		},
	}
	for name, f := range bad {
		if err := f(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrInvalidRequest", name, err)
		}
	}
}

// The browser wallet builds the signed text and signs it in JavaScript. This is a
// signature made by that code (demo-wallet/webtest/interop.test.js pins the same
// vector) with a fixed test key over the pinned message above: if either side's
// idea of the text drifts, one of the two tests fails.
func TestVerifiesASignatureMadeByTheWalletsJavaScript(t *testing.T) {
	const (
		address   = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj"
		signature = "I5Uh4HRDnZhfeAtM260c3m4koTqzH5+88iXNixq/4DNZDXCbGFMYP8vFHsM6lzHFfdakEHfmT2vjPE5Ev3EDDw=="
	)
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyHolder(testChallenge(t), "test", "solana:"+address, sig); err != nil {
		t.Fatalf("a signature made by the wallet's JavaScript was refused: %v", err)
	}
	if err := VerifyHolder(testChallenge(t), "other-token", "solana:"+address, sig); err == nil {
		t.Fatal("the same signature was accepted for a different credential")
	}
}
