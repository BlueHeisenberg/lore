package daemon

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"golang.org/x/crypto/nacl/box"
)

// Direct membership grant — the same admission as the LAN handshake in
// invite.go, with the network and the two humans taken out of it.
//
// The handshake exists because two people who have never exchanged keys need
// something to authenticate each other with, and a code read aloud is it.
// Everything after that authentication is what this file keeps: the owner
// appends a signed member-doc version naming the other account, wraps the
// space key to that account's encryption key inside the document, and seals
// the whole chain to the same key. The grantee verifies the chain, finds
// itself in the latest version, unwraps the key and stores it.
//
// What is removed is only the part that establishes WHO the other party is.
// That is why this is not a widening: the caller of Grant has already opened
// the owner's home and holds its signing key, and the caller of AcceptGrant
// has already opened the grantee's home and holds its encryption key. Neither
// call reaches a second store, and a grant sealed to one account is inert
// everywhere else.

// ErrNotGranted reports a grant blob that is not this account's to apply:
// sealed to another encryption key, corrupt, or naming somebody else in its
// latest member-doc version.
var ErrNotGranted = errors.New("grant is not addressed to this account")

// ErrNotOwner reports an attempt to grant membership of a space this account
// does not own.
var ErrNotOwner = errors.New("not an owner of the space")

// ErrGrantArgument reports a grant call that could not be formed: a role that
// is not grantable, an identity whose encryption key is not bound to its
// account key, this store's own account, or an account already in the member
// list under a different encryption key. Nothing was written.
var ErrGrantArgument = errors.New("grant cannot be formed as asked")

// Grantee is the public half of an account's identity: what a space's owner
// needs to admit it and nothing else. The three fields are exactly what the
// LAN handshake's JoinRequest carries, and EncPubSig is what stops anybody
// pairing their own encryption key with somebody else's identity.
type Grantee struct {
	AccountID string
	EncPub    string
	EncPubSig string
}

// Grant admits to into sp and returns the sealed payload AcceptGrant applies.
//
// st must be the store at home, opened by sp's owner. It is idempotent: an
// account already in the member list gets the current chain re-sealed and no
// new document is written, so a caller may run it on every boot. An account
// already listed under a DIFFERENT encryption key is refused rather than
// re-admitted — the wrapped key in the document would not open for the key
// presented, and failing here says so while failing at the grantee says only
// that the payload will not open.
func Grant(home string, st *store.Store, account *keys.Account, sp store.Space, to Grantee, role string) ([]byte, error) {
	switch {
	case sp.Kind != "shared":
		return nil, store.ErrPersonalSpace
	case role != space.RoleWriter && role != space.RoleReader:
		return nil, fmt.Errorf("%w: role must be writer or reader, got %q", ErrGrantArgument, role)
	case to.AccountID == account.AccountID():
		return nil, fmt.Errorf("%w: that is this store's own account, and a store is already a member of what it owns", ErrGrantArgument)
	}
	if err := verifyEncBinding(to.AccountID, to.EncPub, to.EncPubSig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGrantArgument, err)
	}
	latest, ok, err := st.LatestMemberDoc(sp.SpaceID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("space %s has no verified member list", sp.SpaceID)
	}
	if latest.Role(account.AccountID()) != space.RoleOwner {
		return nil, fmt.Errorf("%w: this account is %q in space %s",
			ErrNotOwner, latest.Role(account.AccountID()), sp.SpaceID)
	}
	granted := role
	if m, already := latest.Member(to.AccountID); already {
		if m.EncPub != to.EncPub {
			return nil, fmt.Errorf("%w: account %s is already a member of %s under a different encryption key",
				ErrGrantArgument, shortID(to.AccountID), sp.SpaceID)
		}
		granted = m.Role
	} else if _, err := admitMember(st, account, sp, to.AccountID, to.EncPub, role); err != nil {
		return nil, err
	}
	return sealInvitePayload(home, sp, granted, to.EncPub)
}

// AcceptGrant applies a grant to the store at home: verify the member-doc
// chain, find this account in the latest version, unwrap the space key and
// store the space and the chain.
//
// It is the tail of the LAN join with the handshake removed, and it takes the
// same three things on faith as that path does — which is to say none. A blob
// sealed to another account does not open. A chain that does not verify is
// refused. A chain that verifies but does not name this account is refused,
// which is what makes a grant unusable by anyone but its addressee even if
// they somehow hold it.
//
// It is idempotent: applying the same grant twice rewrites the same rows.
func AcceptGrant(home string, blob []byte) (JoinResult, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return JoinResult{}, err
	}
	encPub, err := decodeKey32(account.EncPub)
	if err != nil {
		return JoinResult{}, err
	}
	encPriv, err := decodeKey32(account.EncPriv)
	if err != nil {
		return JoinResult{}, err
	}
	plain, ok := box.OpenAnonymous(nil, blob, &encPub, &encPriv)
	if !ok {
		return JoinResult{}, fmt.Errorf("%w: it does not open with this account's encryption key", ErrNotGranted)
	}
	var payload syncproto.InvitePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return JoinResult{}, fmt.Errorf("%w: %v", ErrNotGranted, err)
	}
	p, err := verifyInvitePayload(payload, account, "")
	if err != nil {
		return JoinResult{}, fmt.Errorf("%w: %v", ErrNotGranted, err)
	}
	p.inviterAccount = p.latest.SignedBy
	return persistJoin(home, p)
}

// GranteeOf returns the public half of the identity held at home.
func GranteeOf(home string) (Grantee, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return Grantee{}, err
	}
	return Grantee{
		AccountID: account.AccountID(),
		EncPub:    account.EncPub,
		EncPubSig: account.EncPubSig,
	}, nil
}
