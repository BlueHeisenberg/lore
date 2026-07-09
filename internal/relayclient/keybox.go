package relayclient

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"github.com/BlueHeisenberg/lore/internal/vault"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// KeyboxPayload is the plaintext inside the relay keybox: the full account
// keys PLUS the spaces manifest (ids AND space_keys). account.json alone is
// not enough for a fresh device — without space ids + keys it could not
// compute blinded ids, so it could never find its own logs on the relay.
// The manifest is uploaded by `lore signup` and refreshed by the daemon's
// relay loop whenever the local spaces change (see internal/daemon/relay.go),
// so `lore login` always discovers every space.
type KeyboxPayload struct {
	V         int                     `json:"v"`
	CreatedAt string                  `json:"created_at"`
	Account   keys.Account            `json:"account"`
	Spaces    []syncproto.SpaceRecord `json:"spaces"` // vault Archive's space type, reused
}

// BuildKeyboxPayload assembles the payload from a LORE_HOME: account.json
// plus every spaces row (space_key included) from lore.db.
func BuildKeyboxPayload(home string) (KeyboxPayload, error) {
	var p KeyboxPayload
	account, err := keys.LoadAccount(home)
	if err != nil {
		return p, err
	}
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return p, err
	}
	defer db.Close()
	spaces, err := syncproto.ListSpaceRecords(db)
	if err != nil {
		return p, err
	}
	return KeyboxPayload{V: 1, CreatedAt: keys.Now(), Account: *account, Spaces: spaces}, nil
}

// OpenKeybox decrypts a keybox envelope with the two human factors
// (vault.Open — the same Argon2id keybox crypto as `lore backup`).
func OpenKeybox(envelope []byte, passphrase, recoveryCode string) (KeyboxPayload, error) {
	var p KeyboxPayload
	plain, err := vault.Open(envelope, passphrase, recoveryCode)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(plain, &p); err != nil {
		return p, errors.New("keybox payload is not a lore keybox")
	}
	if p.V != 1 {
		return p, fmt.Errorf("unsupported keybox version %d", p.V)
	}
	if err := p.Account.VerifyEncPub(); err != nil {
		return p, fmt.Errorf("keybox account keys invalid: %w", err)
	}
	return p, nil
}

// --- wrap-key cache: lets the daemon refresh the keybox without secrets ---

// WrapKeyFile holds the cached keybox wrap key under LORE_HOME (0600).
// Threat model: LORE_HOME already stores account.json (the account private
// keys) in plaintext at the same permission level, so caching the derived
// wrap key adds no local exposure — and it never leaves the device. It
// exists so the daemon can re-seal the keybox (updated spaces manifest)
// without ever holding the passphrase or recovery code.
const WrapKeyFile = "keybox.key"

// WrapKey is the cached Argon2id-derived keybox key with the salt/params it
// was derived under. Re-sealing MUST reuse the same salt+params so the
// resulting envelope still opens with the same passphrase + recovery code.
type WrapKey struct {
	V    int             `json:"v"`
	KDF  vault.KDFParams `json:"kdf"`
	Salt []byte          `json:"salt"`
	Key  []byte          `json:"key"`
}

// DeriveWrapKey derives a fresh wrap key (new random salt) from the two
// factors. The derivation (Argon2id over passphrase || normalized recovery
// code) mirrors internal/vault's unexported deriveKey — vault does not
// export it and is owned by parallel work, so it is restated here; the
// cross-compatibility test in test/relayclient pins the two in lockstep
// (a relayclient-sealed envelope MUST open with vault.Open and vice versa).
func DeriveWrapKey(passphrase, recoveryCode string, kdf vault.KDFParams) (WrapKey, error) {
	if kdf == (vault.KDFParams{}) {
		kdf = vault.DefaultKDF
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return WrapKey{}, err
	}
	secret := []byte(passphrase + keys.NormalizeRecoveryCode(recoveryCode))
	key := argon2.IDKey(secret, salt, kdf.Time, kdf.MemoryKiB, kdf.Threads, chacha20poly1305.KeySize)
	return WrapKey{V: 1, KDF: kdf, Salt: salt, Key: key}, nil
}

// SaveWrapKey writes the wrap-key cache (0600) under home.
func SaveWrapKey(home string, wk WrapKey) error {
	b, err := json.MarshalIndent(wk, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(home, WrapKeyFile), append(b, '\n'), 0o600)
}

// LoadWrapKey reads the wrap-key cache. os.ErrNotExist when never cached.
func LoadWrapKey(home string) (WrapKey, error) {
	var wk WrapKey
	b, err := os.ReadFile(filepath.Join(home, WrapKeyFile))
	if err != nil {
		return wk, err
	}
	if err := json.Unmarshal(b, &wk); err != nil {
		return wk, fmt.Errorf("%s: %w", WrapKeyFile, err)
	}
	if wk.V != 1 || len(wk.Key) != chacha20poly1305.KeySize || len(wk.Salt) == 0 {
		return wk, fmt.Errorf("%s: malformed wrap key cache", WrapKeyFile)
	}
	return wk, nil
}

// vaultEnvelope replicates vault's on-disk envelope shape byte-for-byte
// (JSON field names pinned; verified against vault.Open by tests).
type vaultEnvelope struct {
	V     int             `json:"v"`
	KDF   vault.KDFParams `json:"kdf"`
	Salt  []byte          `json:"salt"`
	Nonce []byte          `json:"nonce"`
	Box   []byte          `json:"box"`
}

// keyboxAAD must equal vault's AEAD domain separator.
const keyboxAAD = "lore-backup-v1"

// SealKeyboxWithKey encrypts a keybox payload under a cached wrap key,
// producing an envelope that vault.Open (and therefore `lore login`) opens
// with the original passphrase + recovery code. This is the path the daemon
// uses to refresh the spaces manifest without knowing the secrets.
func SealKeyboxWithKey(p KeyboxPayload, wk WrapKey) ([]byte, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(wk.Key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	box := aead.Seal(nil, nonce, plain, []byte(keyboxAAD))
	return json.MarshalIndent(vaultEnvelope{V: 1, KDF: wk.KDF, Salt: wk.Salt, Nonce: nonce, Box: box}, "", " ")
}
