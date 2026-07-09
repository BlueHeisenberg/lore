package relayclient

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"golang.org/x/crypto/chacha20poly1305"
)

// Delta is the plaintext of one relay log entry (and of a snapshot — a
// snapshot is just a delta carrying the full space state). Same shape as
// the LAN sync push body: entries are author-signed BEFORE encryption, so
// receivers verify signatures + membership on the plaintext and place zero
// trust in the relay.
type Delta struct {
	Entries    []store.Entry         `json:"entries"`
	MemberDocs []syncproto.MemberDoc `json:"member_docs,omitempty"`
}

// EncryptDelta seals a delta with the space_key: XChaCha20-Poly1305,
// random 24-byte nonce prefixed to the ciphertext, AAD = the blinded space
// id string bytes (binds the blob to its log; a relay shuffling blobs
// across spaces produces AEAD failures).
func EncryptDelta(spaceKey []byte, blindedID string, d Delta) ([]byte, error) {
	plain, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(spaceKey)
	if err != nil {
		return nil, fmt.Errorf("relayclient: space key: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(blindedID)), nil
}

// ErrDeltaCorrupt is returned when a relay blob fails authenticated
// decryption (tampered, truncated, or misattributed by the relay).
var ErrDeltaCorrupt = errors.New("relay delta failed authenticated decryption (corrupt or tampered)")

// DecryptDelta opens an EncryptDelta blob. Any tampering — even one flipped
// bit — fails the AEAD tag and returns ErrDeltaCorrupt.
func DecryptDelta(spaceKey []byte, blindedID string, blob []byte) (Delta, error) {
	var d Delta
	aead, err := chacha20poly1305.NewX(spaceKey)
	if err != nil {
		return d, fmt.Errorf("relayclient: space key: %w", err)
	}
	if len(blob) < chacha20poly1305.NonceSizeX {
		return d, ErrDeltaCorrupt
	}
	nonce, box := blob[:chacha20poly1305.NonceSizeX], blob[chacha20poly1305.NonceSizeX:]
	plain, err := aead.Open(nil, nonce, box, []byte(blindedID))
	if err != nil {
		return d, ErrDeltaCorrupt
	}
	if err := json.Unmarshal(plain, &d); err != nil {
		return d, fmt.Errorf("relayclient: delta payload: %w", err)
	}
	return d, nil
}

// ApplyDelta runs the verified receive path on a decrypted delta — the exact
// path LAN sync uses: member docs first (chain-verified via MergeMemberDocs,
// so entries in the same delta are checked against the docs they arrived
// with), then per-entry signature check against the origin device,
// role-checked membership (MemberDocCheck), LWW apply. Returns how many
// entry versions were applied.
func ApplyDelta(st *store.Store, db *sql.DB, sp store.Space, d Delta, ownAccount string) (int, error) {
	if err := syncproto.MergeMemberDocs(db, sp.SpaceID, d.MemberDocs); err != nil {
		return 0, err
	}
	return syncproto.ApplyEntries(st, sp, d.Entries, syncproto.MemberDocCheck(db, ownAccount))
}
