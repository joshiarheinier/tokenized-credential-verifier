package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// storedCredential is one credential held by the wallet. Credential is the
// compact token exactly as the issuer produced it; the other fields are read
// from it for display only. The wallet does not verify credentials: that is the
// verifier's job, and a wallet that trusted its own reading would add nothing.
type storedCredential struct {
	ID             string    `json:"id"`
	Credential     string    `json:"credential"`
	CredentialType string    `json:"credential_type"`
	ExpiresAt      time.Time `json:"expires_at"`
	StoredAt       time.Time `json:"stored_at"`
}

// store keeps one JSON file per credential in a directory only the user can
// read.
type store struct{ dir string }

// save stores token and returns the entry. Saving the same token twice
// overwrites the first copy.
func (s store) save(token string, now time.Time) (storedCredential, error) {
	typ, exp, err := describe(token)
	if err != nil {
		return storedCredential{}, err
	}
	sum := sha256.Sum256([]byte(token))
	c := storedCredential{
		ID:             hex.EncodeToString(sum[:])[:12],
		Credential:     token,
		CredentialType: typ,
		ExpiresAt:      exp,
		StoredAt:       now.UTC(),
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return storedCredential{}, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return storedCredential{}, err
	}
	if err := os.WriteFile(filepath.Join(s.dir, c.ID+".json"), data, 0o600); err != nil {
		return storedCredential{}, err
	}
	return c, nil
}

// list returns the stored credentials, newest first.
func (s store) list() ([]storedCredential, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []storedCredential
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var c storedCredential
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StoredAt.After(out[j].StoredAt) })
	return out, nil
}

// find returns the credential whose id starts with idPrefix, or the newest one
// if idPrefix is empty.
func (s store) find(idPrefix string) (storedCredential, error) {
	all, err := s.list()
	if err != nil {
		return storedCredential{}, err
	}
	var matches []storedCredential
	for _, c := range all {
		if strings.HasPrefix(c.ID, idPrefix) {
			matches = append(matches, c)
		}
	}
	switch {
	case len(matches) == 0 && idPrefix == "":
		return storedCredential{}, errors.New("the wallet is empty: run `demo-wallet request` first")
	case len(matches) == 0:
		return storedCredential{}, fmt.Errorf("no credential with id %q", idPrefix)
	case len(matches) > 1 && idPrefix != "":
		return storedCredential{}, fmt.Errorf("id %q is ambiguous", idPrefix)
	}
	return matches[0], nil
}

// describe reads the type and expiry out of a compact credential without
// verifying it.
func describe(token string) (credentialType string, expiresAt time.Time, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", time.Time{}, errors.New("not a compact credential")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, errors.New("not a compact credential")
	}
	var p struct {
		Type string `json:"credential_type"`
		Exp  int64  `json:"exp"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.Type == "" {
		return "", time.Time{}, errors.New("not a compact credential")
	}
	return p.Type, time.Unix(p.Exp, 0).UTC(), nil
}
