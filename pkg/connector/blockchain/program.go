package blockchain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/gagliardetto/solana-go"
)

// Wire format of the registry program (docs/solana_registry.md). Anchor
// prefixes every instruction and account with an 8-byte discriminator.

var (
	seedRegistryConfig = []byte("registry_config")
	seedIssuer         = []byte("issuer")
	seedCredential     = []byte("credential")
)

// anchorDiscriminator returns the first 8 bytes of sha256("<namespace>:<name>").
func anchorDiscriminator(namespace, name string) [8]byte {
	h := sha256.Sum256([]byte(namespace + ":" + name))
	var d [8]byte
	copy(d[:], h[:8])
	return d
}

var (
	ixInitializeRegistry = anchorDiscriminator("global", "initialize_registry")
	ixRegisterIssuer     = anchorDiscriminator("global", "register_issuer")
	ixSetIssuerStatus    = anchorDiscriminator("global", "set_issuer_status")
	ixRegisterCredential = anchorDiscriminator("global", "register_credential")
	ixRevokeCredential   = anchorDiscriminator("global", "revoke_credential")

	acctRegistryConfig  = anchorDiscriminator("account", "RegistryConfig")
	acctIssuerRecord    = anchorDiscriminator("account", "IssuerRecord")
	acctCredentialState = anchorDiscriminator("account", "CredentialStatus")
)

// Account sizes including the discriminator. Accounts are allocated exactly,
// so any other size means a different layout and is rejected.
const (
	registryConfigSize   = 8 + 32 + 1 + 1 + 1
	issuerRecordSize     = 8 + 32 + 32 + 32 + 1 + 8 + 1
	credentialStatusSize = 8 + 32 + 32 + 1 + 8 + 1
)

type addresses struct{ program solana.PublicKey }

func (a addresses) registryConfig() (solana.PublicKey, error) {
	pk, _, err := solana.FindProgramAddress([][]byte{seedRegistryConfig}, a.program)
	return pk, err
}

func (a addresses) issuer(id [32]byte) (solana.PublicKey, error) {
	pk, _, err := solana.FindProgramAddress([][]byte{seedIssuer, id[:]}, a.program)
	return pk, err
}

func (a addresses) credential(ref [32]byte) (solana.PublicKey, error) {
	pk, _, err := solana.FindProgramAddress([][]byte{seedCredential, ref[:]}, a.program)
	return pk, err
}

// programData is the upgradeable-loader account holding the program's upgrade
// authority; initialize_registry checks it.
func (a addresses) programData() (solana.PublicKey, error) {
	pk, _, err := solana.FindProgramAddress([][]byte{a.program[:]}, solana.BPFLoaderUpgradeableProgramID)
	return pk, err
}

func decodeRegistryConfig(program solana.PublicKey, owner solana.PublicKey, data []byte) (RegistryConfig, error) {
	if err := checkAccount(program, owner, data, acctRegistryConfig, registryConfigSize); err != nil {
		return RegistryConfig{}, fmt.Errorf("registry config: %w", err)
	}
	paused, err := decodeBool(data[40])
	if err != nil {
		return RegistryConfig{}, fmt.Errorf("registry config: paused: %w", err)
	}
	return RegistryConfig{
		Authority: solana.PublicKeyFromBytes(data[8:40]),
		Paused:    paused,
		Version:   data[41],
	}, nil
}

func decodeIssuerRecord(program solana.PublicKey, owner solana.PublicKey, data []byte) (IssuerRecord, error) {
	if err := checkAccount(program, owner, data, acctIssuerRecord, issuerRecordSize); err != nil {
		return IssuerRecord{}, fmt.Errorf("issuer record: %w", err)
	}
	active, err := decodeBool(data[104])
	if err != nil {
		return IssuerRecord{}, fmt.Errorf("issuer record: active: %w", err)
	}
	var rec IssuerRecord
	copy(rec.IssuerID[:], data[8:40])
	rec.SigningKey = append(ed25519.PublicKey(nil), data[40:72]...)
	rec.Authority = solana.PublicKeyFromBytes(data[72:104])
	rec.Active = active
	rec.CreatedAt = time.Unix(int64(binary.LittleEndian.Uint64(data[105:113])), 0).UTC()
	return rec, nil
}

func decodeCredentialStatus(program solana.PublicKey, owner solana.PublicKey, data []byte) (CredentialStatus, error) {
	if err := checkAccount(program, owner, data, acctCredentialState, credentialStatusSize); err != nil {
		return CredentialStatus{}, fmt.Errorf("credential status: %w", err)
	}
	state := CredentialState(data[72])
	if state != CredentialActive && state != CredentialRevoked {
		return CredentialStatus{}, fmt.Errorf("credential status: %w: unknown status %d", ErrInvalidAccount, state)
	}
	var st CredentialStatus
	copy(st.Ref[:], data[8:40])
	copy(st.IssuerID[:], data[40:72])
	st.State = state
	st.ExpiresAt = time.Unix(int64(binary.LittleEndian.Uint64(data[73:81])), 0).UTC()
	return st, nil
}

func checkAccount(program, owner solana.PublicKey, data []byte, disc [8]byte, size int) error {
	if owner != program {
		return fmt.Errorf("%w: not owned by the registry program", ErrInvalidAccount)
	}
	if len(data) != size {
		return fmt.Errorf("%w: size %d, want %d", ErrInvalidAccount, len(data), size)
	}
	if [8]byte(data[:8]) != disc {
		return fmt.Errorf("%w: wrong discriminator", ErrInvalidAccount)
	}
	return nil
}

func decodeBool(b byte) (bool, error) {
	switch b {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, fmt.Errorf("%w: invalid bool %d", ErrInvalidAccount, b)
}

func encodeBool(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// Instruction builders. Account order and mutability mirror the Anchor
// accounts structs (see target/idl/kyc_registry.json).

func (a addresses) initializeRegistryIx(authority solana.PublicKey) (solana.Instruction, error) {
	cfg, err := a.registryConfig()
	if err != nil {
		return nil, err
	}
	pd, err := a.programData()
	if err != nil {
		return nil, err
	}
	return solana.NewInstruction(a.program, solana.AccountMetaSlice{
		solana.Meta(authority).WRITE().SIGNER(),
		solana.Meta(cfg).WRITE(),
		solana.Meta(a.program),
		solana.Meta(pd),
		solana.Meta(solana.SystemProgramID),
	}, ixInitializeRegistry[:]), nil
}

func (a addresses) registerIssuerIx(authority solana.PublicKey, rec IssuerRecord) (solana.Instruction, error) {
	cfg, err := a.registryConfig()
	if err != nil {
		return nil, err
	}
	issuer, err := a.issuer(rec.IssuerID)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 8+96)
	data = append(data, ixRegisterIssuer[:]...)
	data = append(data, rec.IssuerID[:]...)
	data = append(data, rec.SigningKey...)
	data = append(data, rec.Authority[:]...)
	return solana.NewInstruction(a.program, solana.AccountMetaSlice{
		solana.Meta(authority).WRITE().SIGNER(),
		solana.Meta(cfg),
		solana.Meta(issuer).WRITE(),
		solana.Meta(solana.SystemProgramID),
	}, data), nil
}

func (a addresses) setIssuerStatusIx(authority solana.PublicKey, id [32]byte, active bool) (solana.Instruction, error) {
	cfg, err := a.registryConfig()
	if err != nil {
		return nil, err
	}
	issuer, err := a.issuer(id)
	if err != nil {
		return nil, err
	}
	data := append(append([]byte{}, ixSetIssuerStatus[:]...), encodeBool(active))
	return solana.NewInstruction(a.program, solana.AccountMetaSlice{
		solana.Meta(authority).SIGNER(),
		solana.Meta(cfg),
		solana.Meta(issuer).WRITE(),
	}, data), nil
}

func (a addresses) registerCredentialIx(authority solana.PublicKey, issuerID, ref [32]byte, expiresAt time.Time) (solana.Instruction, error) {
	cfg, err := a.registryConfig()
	if err != nil {
		return nil, err
	}
	issuer, err := a.issuer(issuerID)
	if err != nil {
		return nil, err
	}
	cred, err := a.credential(ref)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 8+32+8)
	data = append(data, ixRegisterCredential[:]...)
	data = append(data, ref[:]...)
	data = binary.LittleEndian.AppendUint64(data, uint64(expiresAt.Unix()))
	return solana.NewInstruction(a.program, solana.AccountMetaSlice{
		solana.Meta(authority).WRITE().SIGNER(),
		solana.Meta(cfg),
		solana.Meta(issuer),
		solana.Meta(cred).WRITE(),
		solana.Meta(solana.SystemProgramID),
	}, data), nil
}

func (a addresses) revokeCredentialIx(authority solana.PublicKey, issuerID, ref [32]byte) (solana.Instruction, error) {
	cfg, err := a.registryConfig()
	if err != nil {
		return nil, err
	}
	issuer, err := a.issuer(issuerID)
	if err != nil {
		return nil, err
	}
	cred, err := a.credential(ref)
	if err != nil {
		return nil, err
	}
	return solana.NewInstruction(a.program, solana.AccountMetaSlice{
		solana.Meta(authority).SIGNER(),
		solana.Meta(cfg),
		solana.Meta(issuer),
		solana.Meta(cred).WRITE(),
	}, ixRevokeCredential[:]), nil
}
