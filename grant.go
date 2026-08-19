package lore

import (
	"context"
	"errors"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// Membership across two stores, without a person at each end.
//
// The package doc says membership mutation is not here, and the reason it
// gave is the right one for the case it was written about: a space arrives in
// somebody's store because two people agreed to share, and `lore space invite`
// / `lore join` is that agreement — a code read between humans, a fingerprint
// confirmed on both screens. Software minting memberships for a standalone
// lore user is exactly the thing that must not be possible.
//
// The premise that changed is the same one CreateSpace's did: who the person
// is. An embedder that provisions BOTH stores — a supervisor that created a
// household's pods, holds their configuration, and was told by an
// administrator to add a member — is not a program deciding to share
// somebody's memory. It is a program carrying out a decision already taken,
// against two homes it owns. Making it drive a code and a y/N prompt through
// two containers bought no deliberation; it bought a subprocess and a person
// typing into a pod.
//
// # What is exposed, and where the line is
//
// Two halves that only compose in one direction:
//
//   - GrantMembership is what the OWNER of a space can do with its OWN space.
//     It runs on a Store opened on the owner's home, needs that home's account
//     signing key, and refuses unless that account is an owner in the space's
//     latest verified member list.
//   - AcceptMembership is what a store can do with a grant addressed to
//     ITSELF. It runs on a Store opened on the grantee's home, needs that
//     home's account encryption key, and refuses a grant that does not open
//     with it or whose verified member list does not name it.
//
// Neither call reaches a second store, opens a socket, or takes an identity
// as a parameter that it does not then check cryptographically. There is no
// composition of the two that joins an arbitrary space to an arbitrary
// account: to grant you must already hold the owner's home, and to accept you
// must already hold the grantee's. An embedder that holds both holds both
// anyway — it could read either store's contents directly — so this adds no
// authority it did not have. An embedder that holds one can do exactly what
// the person at that one home could do at the CLI.
//
// What it deliberately does NOT add is removal. lore has no local revocation:
// a member-list version that drops an account can be signed, but every store
// that already holds the space also already holds the key, and a key cannot
// be un-learned. Retiring a member's access means retiring the space. Nothing
// here pretends otherwise.
//
// # This is not the invite handshake and does not replace it
//
// `lore space invite`, `lore join` and the relay invite links are untouched
// and remain the only way two homes that do not share an owner come to share
// a space. They authenticate strangers. These two calls have nothing to
// authenticate strangers WITH, which is precisely why they are only useful to
// a caller that already holds both ends.

// PublicIdentity is the public half of a store's account identity: the three
// values a space's owner needs in order to admit it, and nothing else. No
// private key, no space key, no entry.
//
// EncPubSig is EncPub signed by the account signing key. It is what stops
// anybody pairing their own encryption key with somebody else's account id,
// and GrantMembership verifies it rather than trusting the caller to have.
type PublicIdentity struct {
	// AccountID is the hex Ed25519 account signing key — the same value
	// (*Store).AccountID reports.
	AccountID string
	// EncPub is the hex X25519 account encryption key a space key is wrapped
	// to.
	EncPub string
	// EncPubSig is the hex Ed25519 signature over EncPub by AccountID.
	EncPubSig string
}

// PublicIdentity returns this store's own public identity, to be handed to
// the owner of a space this store should be a member of.
//
// It is safe to publish: everything in it is already on the wire in every
// sync handshake this store performs. A read-only store loads no identity and
// has none to report: ErrReadOnly.
func (s *Store) PublicIdentity() (PublicIdentity, error) {
	switch {
	case s.closed.Load():
		return PublicIdentity{}, ErrClosed
	case s.readOnly:
		return PublicIdentity{}, fmt.Errorf("%w: it loaded no account identity", ErrReadOnly)
	}
	g, err := daemon.GranteeOf(s.home)
	if err != nil {
		return PublicIdentity{}, err
	}
	return PublicIdentity{AccountID: g.AccountID, EncPub: g.EncPub, EncPubSig: g.EncPubSig}, nil
}

// GrantMembership admits to into the shared space spaceID and returns an
// opaque grant for it to apply with AcceptMembership.
//
// This store's account must be an owner of spaceID in its latest verified
// member list, which is the case for a space this store created:
// ErrNotOwner otherwise. role must be Writer or Reader — Owner is not
// grantable, because an owner can grant, and handing that out is a decision
// about who administers a space rather than who reads it.
//
// # The grant
//
// The returned bytes are the space's row, its whole signed member-doc chain
// including the version this call appended, and the space key wrapped to
// to.EncPub inside that chain — sealed as a whole to to.EncPub as well. They
// are opaque and their encoding is not part of this package's promise. They
// are also inert to everybody except to: a grant handed to the wrong store
// does not open, and one that somehow did would still be refused for not
// naming that store's account. So a caller may move them over whatever
// channel it already has, and does not need a confidential one.
//
// # Idempotent, so a caller may call it on every boot
//
// An account already in the member list is not admitted twice: the current
// chain is re-sealed and no new document is written. That is what makes this
// safe to run unconditionally on a supervisor's every pass, and what makes a
// grantee that lost its store recoverable — it asks again and gets the chain
// it is already named in.
//
// An account already listed under a DIFFERENT encryption key is
// ErrInvalidArgument and nothing is written. The wrapped key in the existing
// document was sealed to the old key and would not open for the new one; a
// second entry for one account would be a member list with two answers.
//
// # What it refuses
//
// The personal space, always and on every path: ErrInvalidArgument. An
// identity whose EncPubSig does not verify: ErrInvalidArgument. This store's
// own account: ErrInvalidArgument — a store is already a member of what it
// owns. A read-only store, which cannot sign a member-doc version:
// ErrReadOnly.
func (s *Store) GrantMembership(ctx context.Context, spaceID string, to PublicIdentity, role Role) ([]byte, error) {
	switch {
	case s.closed.Load():
		return nil, ErrClosed
	case s.readOnly:
		return nil, fmt.Errorf("%w: granting membership signs a member-list version", ErrReadOnly)
	case spaceID == "":
		return nil, invalid("spaceID is required")
	case to.AccountID == "" || to.EncPub == "" || to.EncPubSig == "":
		return nil, invalid("to needs AccountID, EncPub and EncPubSig")
	case role != Writer && role != Reader:
		return nil, invalid("role must be %q or %q; ownership is not grantable", Writer, Reader)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sp, err := s.GetSpace(ctx, spaceID)
	if err != nil {
		return nil, err
	}
	if sp.Kind != Shared {
		return nil, invalid("%s is a %s space; only a shared space has members", spaceID, sp.Kind)
	}
	account, err := keys.LoadAccount(s.home)
	if err != nil {
		return nil, err
	}
	var grant []byte
	err = s.do(ctx, func() error {
		row, err := s.st.GetSpace(spaceID)
		if err != nil {
			return err
		}
		grant, err = daemon.Grant(s.home, s.st, account, row, daemon.Grantee{
			AccountID: to.AccountID, EncPub: to.EncPub, EncPubSig: to.EncPubSig,
		}, string(role))
		return err
	})
	if err != nil {
		return nil, grantError(err)
	}
	return grant, nil
}

// AcceptMembership applies a grant made for this store by a space's owner and
// returns the space it joined.
//
// It verifies before it stores, and everything it verifies it verifies
// itself: the blob must open with this store's account encryption key, the
// member-doc chain inside must verify from version 1, the latest version must
// name this store's account, and the space key wrapped to it must unwrap. A
// grant that fails any of those is ErrNotGranted and nothing is written.
//
// The space arrives whole — its id, its key and its member list — so entries
// begin flowing on the next sync round with any peer that also holds it. It
// does not start a daemon; see Serve.
//
// # Idempotent, and it overwrites
//
// Applying the same grant twice writes the same rows twice and is not an
// error. A grant for a space this store ALREADY holds replaces the local row,
// key included — the same rule the join handshake follows, for the same
// reason: enrolment and restore have to reproduce a space verbatim. So do not
// accept a grant for a space this store created itself; that is a space with
// two keys and half its entries will stop being readable.
//
// A read-only store loads no encryption key and can open nothing: ErrReadOnly.
func (s *Store) AcceptMembership(ctx context.Context, grant []byte) (Space, error) {
	switch {
	case s.closed.Load():
		return Space{}, ErrClosed
	case s.readOnly:
		return Space{}, fmt.Errorf("%w: it loaded no account identity to open a grant with", ErrReadOnly)
	case len(grant) == 0:
		return Space{}, invalid("grant is empty")
	}
	if err := ctx.Err(); err != nil {
		return Space{}, err
	}
	var res daemon.JoinResult
	err := s.do(ctx, func() error {
		var err error
		res, err = daemon.AcceptGrant(s.home, grant)
		return err
	})
	if err != nil {
		return Space{}, grantError(err)
	}
	return spaceOf(store.Space{
		SpaceID: res.Space.SpaceID, Kind: res.Space.Kind, Name: res.Space.Name,
		ProjectRef: res.Space.ProjectRef, CreatedAt: res.Space.CreatedAt,
	}), nil
}

// grantError maps internal/daemon's grant failures onto this package's error
// contract. Everything that is not one of the three named conditions is a
// broken store, which wrap already covers.
func grantError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, daemon.ErrNotOwner):
		return fmt.Errorf("%w: %v", ErrNotOwner, err)
	case errors.Is(err, daemon.ErrNotGranted):
		return fmt.Errorf("%w: %v", ErrNotGranted, err)
	case errors.Is(err, daemon.ErrGrantArgument):
		return invalid("%v", err)
	}
	return wrap(err)
}

// The Role vocabulary is internal/space's, spelled twice. Asserted at init so
// a rename on one side cannot silently change what this package grants.
func init() {
	if string(Owner) != space.RoleOwner || string(Writer) != space.RoleWriter || string(Reader) != space.RoleReader {
		panic("lore: Role vocabulary has drifted from internal/space")
	}
}
