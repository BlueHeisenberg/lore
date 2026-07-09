// Package invite implements lore's async invite-link tokens: a short
// human-relayable bearer secret from which both sides derive (a) an opaque
// relay mailbox address and (b) an XChaCha20-Poly1305 key. The owner parks
// an encrypted space payload at the address; the joiner redeems it any time
// before expiry and parks an encrypted claim back. The relay sees only the
// address and ciphertext — never the secret, the space, or the keys.
//
// Token format: 4 words from the embedded BIP39 English list (11 bits each)
// plus a 2-digit number 00-99 (~6.6 bits) — ~50.6 bits of entropy, e.g.
// "maple-rocket-sunset-cactus-73". Parsing is case- and separator-
// insensitive (spaces or dashes) and accepts unique 4-letter word prefixes.
//
// Derivation (S = canonical token string bytes):
//
//	addr      = hex(HMAC-SHA256(S, "lore-invite-addr"))[:32]
//	key       = HMAC-SHA256(S, "lore-invite-key")            (32 bytes)
//	claim MAC = HMAC-SHA256(S, "lore-invite-claim"||account_pub)
//
// Payload blobs are sealed with AAD = addr; claim blobs with AAD =
// addr+"claim", so neither can be replayed at the other slot.
package invite

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Derivation labels (domain separation).
const (
	labelAddr  = "lore-invite-addr"
	labelKey   = "lore-invite-key"
	labelClaim = "lore-invite-claim"
)

// AddrLen is the length of the hex mailbox address.
const AddrLen = 32

// Token is a parsed invite secret: 4 wordlist indices + a 2-digit number.
type Token struct {
	words [4]int // indices into wordlist
	num   int    // 0..99
}

// NewToken mints a random token (crypto/rand).
func NewToken() (Token, error) {
	var t Token
	for i := range t.words {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		if err != nil {
			return Token{}, err
		}
		t.words[i] = int(n.Int64())
	}
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return Token{}, err
	}
	t.num = int(n.Int64())
	return t, nil
}

// ErrBadToken is returned when a string does not parse as an invite token.
var ErrBadToken = errors.New("not an invite token (expected four words and a 2-digit number, e.g. maple-rocket-sunset-cactus-73)")

// ParseToken normalizes and parses a token string: case-insensitive, words
// separated by dashes and/or whitespace, 4 words (full or unique 4-letter
// prefix) followed by a 1-2 digit number.
func ParseToken(s string) (Token, error) {
	fields := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(s)), func(r rune) bool {
		return r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(fields) != 5 {
		return Token{}, ErrBadToken
	}
	var t Token
	for i, w := range fields[:4] {
		idx, ok := wordIndex[w]
		if !ok {
			if len(w) >= 4 {
				idx, ok = prefix4[w[:4]]
			}
			if !ok {
				return Token{}, fmt.Errorf("%w: unknown word %q", ErrBadToken, w)
			}
		}
		t.words[i] = idx
	}
	num := fields[4]
	if len(num) < 1 || len(num) > 2 {
		return Token{}, ErrBadToken
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 0 || n > 99 {
		return Token{}, ErrBadToken
	}
	t.num = n
	return t, nil
}

// IsToken reports whether s parses as an invite token (vs e.g. the 8-char
// LAN invite code, which has no separators and never parses here).
func IsToken(s string) bool {
	_, err := ParseToken(s)
	return err == nil
}

// String renders the canonical form: word-word-word-word-NN (lowercase,
// dashes, zero-padded number). This exact byte string keys every derivation.
func (t Token) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%02d",
		wordlist[t.words[0]], wordlist[t.words[1]],
		wordlist[t.words[2]], wordlist[t.words[3]], t.num)
}

func (t Token) derive(label string) []byte {
	m := hmac.New(sha256.New, []byte(t.String()))
	m.Write([]byte(label))
	return m.Sum(nil)
}

// Addr returns the relay mailbox address: hex(HMAC(S,"lore-invite-addr"))[:32].
func (t Token) Addr() string {
	return hex.EncodeToString(t.derive(labelAddr))[:AddrLen]
}

// key returns the 32-byte XChaCha20-Poly1305 blob key.
func (t Token) key() []byte { return t.derive(labelKey) }

// claimMAC computes the claim binding MAC over the joiner's account pubkey.
func (t Token) claimMAC(accountPub string) []byte {
	m := hmac.New(sha256.New, []byte(t.String()))
	m.Write([]byte(labelClaim))
	m.Write([]byte(accountPub))
	return m.Sum(nil)
}

// Payload is what the owner parks at the invite address: everything the
// joiner needs to adopt the space and start pulling via the relay.
type Payload struct {
	SpaceID      string `json:"space_id"`
	SpaceKey     []byte `json:"space_key"` // 32 bytes (b64 in JSON)
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	ProjectRef   string `json:"project_ref,omitempty"`
	Role         string `json:"role"`
	OwnerAccount string `json:"owner_account"`
	OwnerEncPub  string `json:"owner_enc_pub"`
}

// Claim is what the joiner parks back: its account keys (enc key bound by
// the account signature) plus a token-keyed MAC proving secret possession.
type Claim struct {
	AccountPub string `json:"account_pub"`
	EncPub     string `json:"enc_pub"`
	EncPubSig  string `json:"enc_pub_sig"`
	Name       string `json:"name"` // joiner display name (device/host)
	MAC        string `json:"mac"`  // hex HMAC(S, "lore-invite-claim"||account_pub)
}

// NewClaim builds a claim for the joiner's account keys with a valid MAC.
func NewClaim(t Token, accountPub, encPub, encPubSig, name string) Claim {
	return Claim{
		AccountPub: accountPub,
		EncPub:     encPub,
		EncPubSig:  encPubSig,
		Name:       name,
		MAC:        hex.EncodeToString(t.claimMAC(accountPub)),
	}
}

// Verify checks the claim MAC against the token. The enc_pub_sig binding is
// the processor's job (it needs the account-key verification helper).
func (c Claim) Verify(t Token) error {
	mac, err := hex.DecodeString(c.MAC)
	if err != nil || !hmac.Equal(mac, t.claimMAC(c.AccountPub)) {
		return errors.New("invite claim MAC does not verify (wrong token or forged claim)")
	}
	return nil
}

// ErrBlobCorrupt is returned when a blob fails authenticated decryption.
var ErrBlobCorrupt = errors.New("invite blob failed authenticated decryption (wrong token, corrupt, or tampered)")

// seal encrypts plain under the token key: XChaCha20-Poly1305, random
// 24-byte nonce prefixed, AAD binds the blob to its slot.
func seal(t Token, aad string, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(t.key())
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

func open(t Token, aad string, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(t.key())
	if err != nil {
		return nil, err
	}
	if len(blob) < chacha20poly1305.NonceSizeX {
		return nil, ErrBlobCorrupt
	}
	nonce, box := blob[:chacha20poly1305.NonceSizeX], blob[chacha20poly1305.NonceSizeX:]
	plain, err := aead.Open(nil, nonce, box, []byte(aad))
	if err != nil {
		return nil, ErrBlobCorrupt
	}
	return plain, nil
}

// SealPayload encrypts the owner's payload for the invite address (AAD=addr).
func SealPayload(t Token, p Payload) ([]byte, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return seal(t, t.Addr(), plain)
}

// OpenPayload decrypts and parses a payload blob.
func OpenPayload(t Token, blob []byte) (Payload, error) {
	plain, err := open(t, t.Addr(), blob)
	if err != nil {
		return Payload{}, err
	}
	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return Payload{}, fmt.Errorf("invite payload: %w", err)
	}
	return p, nil
}

// SealClaim encrypts a joiner claim (AAD=addr+"claim").
func SealClaim(t Token, c Claim) ([]byte, error) {
	plain, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return seal(t, t.Addr()+"claim", plain)
}

// OpenClaim decrypts and parses a claim blob AND verifies its MAC.
func OpenClaim(t Token, blob []byte) (Claim, error) {
	plain, err := open(t, t.Addr()+"claim", blob)
	if err != nil {
		return Claim{}, err
	}
	var c Claim
	if err := json.Unmarshal(plain, &c); err != nil {
		return Claim{}, fmt.Errorf("invite claim: %w", err)
	}
	if err := c.Verify(t); err != nil {
		return Claim{}, err
	}
	return c, nil
}
