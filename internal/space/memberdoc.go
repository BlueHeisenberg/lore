package space

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Member roles. Owners administer the member list; writers may add entries;
// readers only receive.
const (
	RoleOwner  = "owner"
	RoleWriter = "writer"
	RoleReader = "reader"
)

// ValidRole reports whether r is a known member role.
func ValidRole(r string) bool {
	return r == RoleOwner || r == RoleWriter || r == RoleReader
}

// Member is one entry of a signed member list.
type Member struct {
	AccountPub      string `json:"account_pub"`       // hex Ed25519 account signing pubkey
	EncPub          string `json:"enc_pub"`           // hex X25519 account encryption pubkey
	Role            string `json:"role"`              // owner | writer | reader
	WrappedSpaceKey string `json:"wrapped_space_key"` // base64(box.SealAnonymous(space_key, enc_pub))
}

// MemberDoc is a whole signed member-list document, one version of a space's
// membership. The signature (account signing key of SignedBy) covers the
// canonical JSON of everything except Sig.
type MemberDoc struct {
	SpaceID  string   `json:"space_id"`
	Version  int64    `json:"version"`
	Members  []Member `json:"members"`
	SignedBy string   `json:"signed_by"` // hex account signing pubkey
	SignedAt string   `json:"signed_at"`
	Sig      string   `json:"sig"` // hex Ed25519 over SHA-256(canonical doc sans sig)
}

// canonicalMemberDoc pins the signing encoding: JSON with keys sorted
// (struct declaration order below IS the sorted order), no insignificant
// whitespace, sig excluded.
type canonicalMemberDoc struct {
	Members  []Member `json:"members"`
	SignedAt string   `json:"signed_at"`
	SignedBy string   `json:"signed_by"`
	SpaceID  string   `json:"space_id"`
	Version  int64    `json:"version"`
}

// CanonicalBytes returns the canonical signing encoding (sig excluded).
// Members are serialized in the doc's order; builders sort by account_pub.
func (d MemberDoc) CanonicalBytes() ([]byte, error) {
	m := d.Members
	if m == nil {
		m = []Member{}
	}
	return json.Marshal(canonicalMemberDoc{
		Members:  m,
		SignedAt: d.SignedAt,
		SignedBy: d.SignedBy,
		SpaceID:  d.SpaceID,
		Version:  d.Version,
	})
}

// DocJSON is the canonical document body as stored in the member_docs `doc`
// column and carried on the wire (sig travels separately).
func (d MemberDoc) DocJSON() (string, error) {
	b, err := d.CanonicalBytes()
	return string(b), err
}

// ParseMemberDoc reconstructs a MemberDoc from its stored (doc, sig) pair.
func ParseMemberDoc(docJSON, sig string) (MemberDoc, error) {
	var c canonicalMemberDoc
	if err := json.Unmarshal([]byte(docJSON), &c); err != nil {
		return MemberDoc{}, fmt.Errorf("member doc: %w", err)
	}
	return MemberDoc{
		SpaceID:  c.SpaceID,
		Version:  c.Version,
		Members:  c.Members,
		SignedBy: c.SignedBy,
		SignedAt: c.SignedAt,
		Sig:      sig,
	}, nil
}

// Sign sets SignedAt (if empty) and Sig using the signer's account key.
// SignedBy must already name the signer's account pubkey.
func (d *MemberDoc) Sign(accountPriv ed25519.PrivateKey) error {
	if d.SignedAt == "" {
		d.SignedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	}
	b, err := d.CanonicalBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	d.Sig = hex.EncodeToString(ed25519.Sign(accountPriv, sum[:]))
	return nil
}

// VerifySig checks the document signature against SignedBy. It says nothing
// about whether SignedBy was AUTHORIZED to sign this version — that is the
// chain rule (VerifiedDocs).
func (d MemberDoc) VerifySig() error {
	pub, err := hex.DecodeString(d.SignedBy)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("member doc: invalid signed_by key")
	}
	sig, err := hex.DecodeString(d.Sig)
	if err != nil {
		return errors.New("member doc: invalid signature encoding")
	}
	b, err := d.CanonicalBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if !ed25519.Verify(ed25519.PublicKey(pub), sum[:], sig) {
		return errors.New("member doc signature does not verify")
	}
	return nil
}

// Member returns the member entry for an account, if present.
func (d MemberDoc) Member(accountPub string) (Member, bool) {
	for _, m := range d.Members {
		if m.AccountPub == accountPub {
			return m, true
		}
	}
	return Member{}, false
}

// Role returns the account's role in the doc, "" if not a member.
func (d MemberDoc) Role(accountPub string) string {
	m, ok := d.Member(accountPub)
	if !ok {
		return ""
	}
	return m.Role
}

// CanWrite reports whether the account may author entries under this doc.
func (d MemberDoc) CanWrite(accountPub string) bool {
	r := d.Role(accountPub)
	return r == RoleOwner || r == RoleWriter
}

// sortMembers orders members by account_pub for a deterministic encoding.
func sortMembers(members []Member) []Member {
	out := append([]Member(nil), members...)
	sort.Slice(out, func(i, j int) bool { return out[i].AccountPub < out[j].AccountPub })
	return out
}

// NewMemberDoc builds and signs member-list version 1 for a space: the
// creator as sole owner. Its self-signature is what defines the owner for
// the whole chain.
func NewMemberDoc(spaceID string, owner Member, accountPriv ed25519.PrivateKey) (MemberDoc, error) {
	owner.Role = RoleOwner
	d := MemberDoc{
		SpaceID:  spaceID,
		Version:  1,
		Members:  []Member{owner},
		SignedBy: owner.AccountPub,
	}
	if err := d.Sign(accountPriv); err != nil {
		return MemberDoc{}, err
	}
	return d, nil
}

// Evolve builds and signs the next member-list version with a new member
// set. signerAccount must be an owner of prev (enforced here as a guard;
// receivers re-verify via the chain rule regardless).
func Evolve(prev MemberDoc, members []Member, signerAccount string, accountPriv ed25519.PrivateKey) (MemberDoc, error) {
	if prev.Role(signerAccount) != RoleOwner {
		return MemberDoc{}, fmt.Errorf("account %s is not an owner of space %s (v%d)",
			signerAccount, prev.SpaceID, prev.Version)
	}
	for _, m := range members {
		if !ValidRole(m.Role) {
			return MemberDoc{}, fmt.Errorf("invalid role %q for member %s", m.Role, m.AccountPub)
		}
	}
	d := MemberDoc{
		SpaceID:  prev.SpaceID,
		Version:  prev.Version + 1,
		Members:  sortMembers(members),
		SignedBy: signerAccount,
	}
	if err := d.Sign(accountPriv); err != nil {
		return MemberDoc{}, err
	}
	return d, nil
}

// RawDoc is a member_docs row as stored/transferred: version + canonical doc
// JSON + detached signature.
type RawDoc struct {
	Version int64
	Doc     string
	Sig     string
}

// VerifiedDocs validates the signed member-doc chain for spaceID and
// returns the accepted prefix, oldest first. The rule:
//
//   - version 1 defines the owner: it must verify against its own SignedBy,
//     and SignedBy must be listed in it as an owner;
//   - every later version must have version = previous accepted version + 1
//     and be signed by an account that holds the owner role in the LATEST
//     previously accepted version.
//
// The first failing document ends the chain — later versions cannot be
// authorized by an unverified predecessor.
func VerifiedDocs(spaceID string, raws []RawDoc) []MemberDoc {
	sorted := append([]RawDoc(nil), raws...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Version < sorted[j].Version })

	var accepted []MemberDoc
	for _, r := range sorted {
		d, err := ParseMemberDoc(r.Doc, r.Sig)
		if err != nil {
			break
		}
		if d.SpaceID != spaceID || d.Version != r.Version {
			break
		}
		if err := d.VerifySig(); err != nil {
			break
		}
		if len(accepted) == 0 {
			if d.Version != 1 || d.Role(d.SignedBy) != RoleOwner {
				break
			}
		} else {
			prev := accepted[len(accepted)-1]
			if d.Version != prev.Version+1 || prev.Role(d.SignedBy) != RoleOwner {
				break
			}
		}
		accepted = append(accepted, d)
	}
	return accepted
}

// LatestDoc returns the newest verified member doc of the chain, if any.
func LatestDoc(spaceID string, raws []RawDoc) (MemberDoc, bool) {
	docs := VerifiedDocs(spaceID, raws)
	if len(docs) == 0 {
		return MemberDoc{}, false
	}
	return docs[len(docs)-1], true
}

// WrapSpaceKey seals the space key to a member's X25519 encryption pubkey
// (hex) with an anonymous NaCl box; the result is base64 for the member doc.
func WrapSpaceKey(spaceKey []byte, encPubHex string) (string, error) {
	pub, err := decode32(encPubHex)
	if err != nil {
		return "", fmt.Errorf("enc pubkey: %w", err)
	}
	sealed, err := box.SealAnonymous(nil, spaceKey, &pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// UnwrapSpaceKey opens a wrapped space key with the member's X25519 keypair.
func UnwrapSpaceKey(wrapped, encPubHex, encPrivHex string) ([]byte, error) {
	pub, err := decode32(encPubHex)
	if err != nil {
		return nil, fmt.Errorf("enc pubkey: %w", err)
	}
	priv, err := decode32(encPrivHex)
	if err != nil {
		return nil, fmt.Errorf("enc privkey: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("wrapped space key: %w", err)
	}
	key, ok := box.OpenAnonymous(nil, sealed, &pub, &priv)
	if !ok {
		return nil, errors.New("wrapped space key does not open with this account's encryption key")
	}
	return key, nil
}

func decode32(hexKey string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("bad key length %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}
