package registry

import (
	"encoding/hex"
	"testing"
)

func TestRefsAreDeterministicAndDomainSeparated(t *testing.T) {
	if IssuerID("a") != IssuerID("a") || CredentialRef("a") != CredentialRef("a") {
		t.Fatal("refs must be deterministic")
	}
	if IssuerID("a") == IssuerID("b") || CredentialRef("a") == CredentialRef("b") {
		t.Fatal("different inputs must map to different refs")
	}
	if IssuerID("x") == CredentialRef("x") {
		t.Fatal("issuer ids and credential refs must not collide for the same input")
	}
}

// The ids are stored in registries, so changing how they are derived orphans
// every existing record. These values pin the derivation.
func TestIdDerivationIsPinned(t *testing.T) {
	issuer := IssuerID("did:example:issuer")
	if got, want := hex.EncodeToString(issuer[:]), "c2ba315442914f8c3b5bf66d1efbc241d16e75c41da07fb29933c64aae2076ef"; got != want {
		t.Errorf("IssuerID = %s, want %s", got, want)
	}
	ref := CredentialRef("abc")
	if got, want := hex.EncodeToString(ref[:]), "0e0a9407b3d949d804321b92c2792bfb1686d971a6d844fc070f2d25c5712e26"; got != want {
		t.Errorf("CredentialRef = %s, want %s", got, want)
	}
}
