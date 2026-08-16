// Package keys implements lore's identity layer: the account keypairs
// (Ed25519 signing + X25519 encryption), per-device keys with device
// certificates signed by the account key, and recovery-code generation.
// Formats are pinned by docs/IMPLEMENTATION.md.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	AccountFile = "account.json"
	DeviceFile  = "device.json"
)

// TimeFormat is RFC3339 with fixed-width nanoseconds (UTC), lexicographically
// sortable — which is what lets a stored timestamp be compared as a string.
const TimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

// Now returns the current UTC time in lore's canonical timestamp format.
func Now() string { return time.Now().UTC().Format(TimeFormat) }

// Account holds the two account keypairs. All key fields are hex.
type Account struct {
	V         int    `json:"v"`
	SignPriv  string `json:"sign_priv"`
	SignPub   string `json:"sign_pub"`
	EncPriv   string `json:"enc_priv"`
	EncPub    string `json:"enc_pub"`
	EncPubSig string `json:"enc_pub_sig"`
	CreatedAt string `json:"created_at"`
}

// AccountID is the account identity: hex of the Ed25519 signing pubkey.
func (a *Account) AccountID() string { return a.SignPub }

// SigningKey decodes the Ed25519 private signing key.
func (a *Account) SigningKey() (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(a.SignPriv)
	if err != nil {
		return nil, fmt.Errorf("account sign_priv: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("account sign_priv: bad length %d", len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// GenerateAccount creates a fresh account: an Ed25519 signing pair and a
// separate X25519 encryption pair whose pubkey is signed by the signing key.
func GenerateAccount() (*Account, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encPriv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(encPriv); err != nil {
		return nil, err
	}
	encPub, err := curve25519.X25519(encPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(signPriv, encPub)
	return &Account{
		V:         1,
		SignPriv:  hex.EncodeToString(signPriv),
		SignPub:   hex.EncodeToString(signPub),
		EncPriv:   hex.EncodeToString(encPriv),
		EncPub:    hex.EncodeToString(encPub),
		EncPubSig: hex.EncodeToString(sig),
		CreatedAt: Now(),
	}, nil
}

// VerifyEncPub checks that the encryption pubkey is signed by the account signing key.
func (a *Account) VerifyEncPub() error {
	signPub, err := hex.DecodeString(a.SignPub)
	if err != nil || len(signPub) != ed25519.PublicKeySize {
		return errors.New("account sign_pub invalid")
	}
	encPub, err := hex.DecodeString(a.EncPub)
	if err != nil {
		return errors.New("account enc_pub invalid")
	}
	sig, err := hex.DecodeString(a.EncPubSig)
	if err != nil {
		return errors.New("account enc_pub_sig invalid")
	}
	if !ed25519.Verify(ed25519.PublicKey(signPub), encPub, sig) {
		return errors.New("enc_pub signature does not verify against account signing key")
	}
	return nil
}

// DeviceCert is the device certificate: the device pubkey bound to an account
// by a signature from the account signing key.
type DeviceCert struct {
	DevicePub  string `json:"device_pub"`
	AccountPub string `json:"account_pub"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	Sig        string `json:"sig"`
}

// certSigningBytes is the canonical encoding the account key signs:
// JSON with keys sorted, no insignificant whitespace, sig field excluded.
func (c *DeviceCert) certSigningBytes() []byte {
	// Struct field order is the sorted key order.
	payload := struct {
		AccountPub string `json:"account_pub"`
		CreatedAt  string `json:"created_at"`
		DevicePub  string `json:"device_pub"`
		Name       string `json:"name"`
	}{c.AccountPub, c.CreatedAt, c.DevicePub, c.Name}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return sum[:]
}

// Verify checks the certificate signature against the account pubkey embedded in it.
func (c *DeviceCert) Verify() error {
	accountPub, err := hex.DecodeString(c.AccountPub)
	if err != nil || len(accountPub) != ed25519.PublicKeySize {
		return errors.New("device cert account_pub invalid")
	}
	sig, err := hex.DecodeString(c.Sig)
	if err != nil {
		return errors.New("device cert sig invalid")
	}
	if !ed25519.Verify(ed25519.PublicKey(accountPub), c.certSigningBytes(), sig) {
		return errors.New("device certificate does not verify against account key")
	}
	return nil
}

// VerifyForAccount additionally pins the cert to an expected account id (hex signing pubkey).
func (c *DeviceCert) VerifyForAccount(accountID string) error {
	if c.AccountPub != accountID {
		return errors.New("device certificate issued by a different account")
	}
	return c.Verify()
}

// Device is a per-device Ed25519 keypair plus its account-signed certificate.
type Device struct {
	V          int        `json:"v"`
	DevicePriv string     `json:"device_priv"`
	DevicePub  string     `json:"device_pub"`
	Name       string     `json:"name"`
	Cert       DeviceCert `json:"cert"`
}

// DeviceID is the device identity: hex of the device pubkey.
func (d *Device) DeviceID() string { return d.DevicePub }

// PrivateKey decodes the device's Ed25519 private key.
func (d *Device) PrivateKey() (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(d.DevicePriv)
	if err != nil {
		return nil, fmt.Errorf("device_priv: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("device_priv: bad length %d", len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// GenerateDevice creates a device keypair and certifies it with the account key.
func GenerateDevice(name string, account *Account) (*Device, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signKey, err := account.SigningKey()
	if err != nil {
		return nil, err
	}
	cert := DeviceCert{
		DevicePub:  hex.EncodeToString(pub),
		AccountPub: account.SignPub,
		Name:       name,
		CreatedAt:  Now(),
	}
	cert.Sig = hex.EncodeToString(ed25519.Sign(signKey, cert.certSigningBytes()))
	return &Device{
		V:          1,
		DevicePriv: hex.EncodeToString(priv),
		DevicePub:  hex.EncodeToString(pub),
		Name:       name,
		Cert:       cert,
	}, nil
}

func writeJSON0600(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// SaveAccount writes account.json (0600) under dir.
func SaveAccount(dir string, a *Account) error {
	return writeJSON0600(filepath.Join(dir, AccountFile), a)
}

// SaveDevice writes device.json (0600) under dir.
func SaveDevice(dir string, d *Device) error {
	return writeJSON0600(filepath.Join(dir, DeviceFile), d)
}

// LoadAccount reads account.json from dir, erroring clearly if absent or invalid.
func LoadAccount(dir string) (*Account, error) {
	path := filepath.Join(dir, AccountFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no account at %s (run `lore init`)", path)
	}
	if err != nil {
		return nil, err
	}
	var a Account
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if a.V != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d", path, a.V)
	}
	if err := a.VerifyEncPub(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &a, nil
}

// LoadDevice reads device.json from dir, erroring clearly if absent or invalid.
func LoadDevice(dir string) (*Device, error) {
	path := filepath.Join(dir, DeviceFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no device at %s (run `lore init`)", path)
	}
	if err != nil {
		return nil, err
	}
	var d Device
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if d.V != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d", path, d.V)
	}
	if err := d.Cert.Verify(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &d, nil
}

// crockford is the Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// RecoveryCodeGroups / RecoveryCodeGroupLen pin the recovery-code shape:
// 10 hyphen-separated groups of 4 Crockford-base32 chars (200 bits entropy).
const (
	RecoveryCodeGroups   = 10
	RecoveryCodeGroupLen = 4
)

// NewRecoveryCode generates the account recovery code: 25 random bytes
// (200 bits) encoded as 40 Crockford-base32 chars in 10 groups of 4.
func NewRecoveryCode() (string, error) {
	nChars := RecoveryCodeGroups * RecoveryCodeGroupLen // 40
	raw := make([]byte, nChars*5/8)                     // 25 bytes
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	chars := make([]byte, 0, nChars)
	var acc, bits uint
	for _, b := range raw {
		acc = acc<<8 | uint(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			chars = append(chars, crockford[(acc>>bits)&31])
		}
	}
	groups := make([]string, RecoveryCodeGroups)
	for i := range groups {
		groups[i] = string(chars[i*RecoveryCodeGroupLen : (i+1)*RecoveryCodeGroupLen])
	}
	return strings.Join(groups, "-"), nil
}

// NormalizeRecoveryCode canonicalizes user input for comparison: uppercase,
// separators stripped, Crockford aliases folded (I/L -> 1, O -> 0).
func NormalizeRecoveryCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case '-', ' ', '\t':
			continue
		case 'I', 'L':
			b.WriteRune('1')
		case 'O':
			b.WriteRune('0')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
