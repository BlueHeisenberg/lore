// Package vault implements lore's encrypted backup archive and the keybox
// crypto that protects it: XChaCha20-Poly1305 under a key derived with
// Argon2id from (passphrase || recovery_code). Pinned by
// docs/IMPLEMENTATION.md §Space crypto (keybox part).
package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// KDFParams pin the Argon2id cost. The archive header records the params
// used, so Open works regardless of what Seal was configured with — this is
// the internal knob tests use to avoid 64 MiB hashes.
type KDFParams struct {
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
}

// DefaultKDF is the production cost: t=3, m=64MiB, p=4 (contract-pinned).
var DefaultKDF = KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// keyboxAAD domain-separates the AEAD.
const keyboxAAD = "lore-backup-v1"

// file is the on-disk envelope (JSON, everything binary base64-encoded by
// encoding/json's []byte handling).
type file struct {
	V     int       `json:"v"`
	KDF   KDFParams `json:"kdf"`
	Salt  []byte    `json:"salt"`
	Nonce []byte    `json:"nonce"`
	Box   []byte    `json:"box"`
}

func deriveKey(passphrase, recoveryCode string, salt []byte, kdf KDFParams) []byte {
	secret := []byte(passphrase + keys.NormalizeRecoveryCode(recoveryCode))
	return argon2.IDKey(secret, salt, kdf.Time, kdf.MemoryKiB, kdf.Threads, chacha20poly1305.KeySize)
}

// Seal encrypts plaintext into the archive envelope. kdf zero-value means
// DefaultKDF.
func Seal(plaintext []byte, passphrase, recoveryCode string, kdf KDFParams) ([]byte, error) {
	if kdf == (KDFParams{}) {
		kdf = DefaultKDF
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := deriveKey(passphrase, recoveryCode, salt, kdf)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, []byte(keyboxAAD))
	return json.MarshalIndent(file{V: 1, KDF: kdf, Salt: salt, Nonce: nonce, Box: sealed}, "", " ")
}

// Open decrypts an archive envelope produced by Seal.
func Open(envelope []byte, passphrase, recoveryCode string) ([]byte, error) {
	var f file
	if err := json.Unmarshal(envelope, &f); err != nil {
		return nil, fmt.Errorf("not a lore backup file: %w", err)
	}
	if f.V != 1 {
		return nil, fmt.Errorf("unsupported backup version %d", f.V)
	}
	key := deriveKey(passphrase, recoveryCode, f.Salt, f.KDF)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(f.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("corrupt backup: bad nonce")
	}
	plain, err := aead.Open(nil, f.Nonce, f.Box, []byte(keyboxAAD))
	if err != nil {
		return nil, errors.New("cannot decrypt backup: wrong passphrase/recovery code, or file corrupted")
	}
	return plain, nil
}

// Archive is the backup plaintext: the account keybox content, every space
// row (including space_keys), member docs, all entry versions (tombstones
// included), the attachments manifest, and blob bytes.
type Archive struct {
	V           int                              `json:"v"`
	CreatedAt   string                           `json:"created_at"`
	Account     keys.Account                     `json:"account"`
	Spaces      []syncproto.SpaceRecord          `json:"spaces"`
	MemberDocs  map[string][]syncproto.MemberDoc `json:"member_docs"` // space_id -> docs
	Entries     []store.Entry                    `json:"entries"`
	Attachments []syncproto.AttachmentRow        `json:"attachments"`
	Blobs       map[string][]byte                `json:"blobs"` // blob_hash -> bytes
}
