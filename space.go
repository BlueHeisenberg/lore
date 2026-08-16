package lore

import (
	"context"
	"errors"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// SpaceKind distinguishes the single personal space from shared ones.
type SpaceKind string

const (
	// Personal is the one space that never accepts members and that the
	// user-model layers (profile/, feedback/) never leave.
	Personal SpaceKind = "personal"
	// Shared is a project or topic space with a member list.
	Shared SpaceKind = "shared"
)

// Space is a sharing unit. The space key is not reported: it is the
// encryption key the sync and relay layers wrap to members, and nothing
// outside lore has a use for it.
type Space struct {
	ID   string
	Kind SpaceKind

	// Name is a local display name. lore does not enforce uniqueness and it
	// is not stable across stores. Configure by ID; never compare names as a
	// proxy for identity.
	Name string

	// ProjectRef is set on a space bound to a git project, empty otherwise.
	ProjectRef string

	// Pinned marks a space that joins the CLI's default search scope. It has
	// no meaning to a caller that passes explicit space sets.
	Pinned bool

	CreatedAt Timestamp
}

func spaceOf(sp store.Space) Space {
	return Space{
		ID:         sp.SpaceID,
		Kind:       SpaceKind(sp.Kind),
		Name:       sp.Name,
		ProjectRef: sp.ProjectRef,
		Pinned:     sp.Pinned,
		CreatedAt:  Timestamp(sp.CreatedAt),
	}
}

// Role is a member's role in a shared space.
type Role string

const (
	Owner  Role = "owner"  // administers the member list
	Writer Role = "writer" // may author entries
	Reader Role = "reader" // receives only
)

// Member is one account's membership of a space. The wrapped space key and
// the encryption public key are not reported.
type Member struct {
	AccountID string // hex Ed25519 account signing key
	Role      Role
}

// Spaces lists every space this store holds, personal first then by name.
//
// Locally present is the membership check: a space this store does not hold
// was never synced here, and there is no way to ask for one that was not.
func (s *Store) Spaces(ctx context.Context) ([]Space, error) {
	var sps []store.Space
	err := s.do(ctx, func() error {
		var err error
		sps, err = s.st.ListSpaces()
		return err
	})
	if err != nil || sps == nil {
		return nil, err
	}
	out := make([]Space, len(sps))
	for i, sp := range sps {
		out[i] = spaceOf(sp)
	}
	return out, nil
}

// CreateSpace creates a shared space owned by this store's account and
// returns it, id included — so nothing ever has to diff a listing to find out
// what was made.
//
// It does the whole creation, not the row: a fresh space key, the space, and
// signed member-list v1 naming this account sole owner with its wrapped copy
// of the key inside. Those are one transaction. A space without that document
// is one nobody can prove they own and nobody can be invited into.
//
// kind must be Shared. The personal space is Init's: there is exactly one per
// home, it never accepts members, and asking for another here is
// ErrInvalidArgument rather than a second one. So is the name "personal",
// which resolves to the personal space everywhere lore takes a name.
//
// A name already held by a space in this store is ErrSpaceExists. That is a
// local guard and not a uniqueness promise — see Space.Name — but it is the
// one that stops a wizard from making a member's space twice.
//
// ErrBusy is not retried here, unlike every other write in this package: this
// is two statements, and a replay is only safe for an operation that
// committed nothing. Call it again yourself if you want to.
//
// A read-only store loads no signing identity and so cannot own anything:
// ErrReadOnly.
func (s *Store) CreateSpace(ctx context.Context, name string, kind SpaceKind) (Space, error) {
	switch {
	case name == "":
		return Space{}, invalid("name is required")
	case name == "personal":
		return Space{}, invalid(`the name "personal" is reserved for the personal space`)
	case kind != Shared:
		return Space{}, invalid("kind must be %q; the personal space is created by Init", Shared)
	}
	// The name lookup is also this call's closed-store and context check: it
	// runs before anything is written and reports both.
	switch _, err := s.SpaceByName(ctx, name); {
	case err == nil:
		return Space{}, fmt.Errorf("%w: %q", ErrSpaceExists, name)
	case !errors.Is(err, ErrSpaceNotFound):
		return Space{}, err
	}
	// The account signing key is loaded here and held nowhere: it certifies
	// devices, so a long-lived Store keeping it in memory would be a worse
	// trade than one file read on a rare call.
	account, err := keys.LoadAccount(s.home)
	if err != nil {
		return Space{}, err
	}
	priv, err := account.SigningKey()
	if err != nil {
		return Space{}, err
	}
	sp, err := s.st.CreateSharedSpace(name, "", account.EncPub, priv)
	if err != nil {
		return Space{}, wrap(err)
	}
	return spaceOf(sp), nil
}

// GetSpace returns a space by id, or ErrSpaceNotFound.
func (s *Store) GetSpace(ctx context.Context, spaceID string) (Space, error) {
	if spaceID == "" {
		return Space{}, invalid("spaceID is required")
	}
	return s.space(ctx, func() (store.Space, error) { return s.st.GetSpace(spaceID) })
}

// SpaceByName returns a space by display name, or ErrSpaceNotFound.
//
// Names are neither unique nor stable across stores; if two match, which one
// you get is unspecified. Resolve a name once, at a boundary where a human
// typed it, and carry the id afterwards.
func (s *Store) SpaceByName(ctx context.Context, name string) (Space, error) {
	if name == "" {
		return Space{}, invalid("name is required")
	}
	return s.space(ctx, func() (store.Space, error) { return s.st.SpaceByName(name) })
}

// PersonalSpace returns the single personal space, or ErrSpaceNotFound when
// the home has none (an uninitialised store).
func (s *Store) PersonalSpace(ctx context.Context) (Space, error) {
	return s.space(ctx, s.st.PersonalSpace)
}

func (s *Store) space(ctx context.Context, get func() (store.Space, error)) (Space, error) {
	var sp store.Space
	err := s.do(ctx, func() error {
		var err error
		sp, err = get()
		return err
	})
	if err != nil {
		return Space{}, err
	}
	return spaceOf(sp), nil
}

// Members returns the members of a space according to its latest verified
// member list, or nil when it has none — which is the pre-membership state a
// shared space starts in, and the permanent state of the personal space.
//
// Only verified documents count: an unsigned or badly-chained member list is
// the same as no member list, never a partially trusted one.
func (s *Store) Members(ctx context.Context, spaceID string) ([]Member, error) {
	if spaceID == "" {
		return nil, invalid("spaceID is required")
	}
	doc, ok, err := s.memberDoc(ctx, spaceID)
	if err != nil || !ok {
		return nil, err
	}
	out := make([]Member, 0, len(doc.Members))
	for _, m := range doc.Members {
		out = append(out, Member{AccountID: m.AccountPub, Role: Role(m.Role)})
	}
	return out, nil
}

// CanWrite reports whether this store's account may author into a space.
// A space with no verified member list is writable, and so is the personal
// space. A read-only store can never write, so this is always false on one.
func (s *Store) CanWrite(ctx context.Context, spaceID string) (bool, error) {
	if s.readOnly {
		return false, nil
	}
	sp, err := s.GetSpace(ctx, spaceID)
	if err != nil {
		return false, err
	}
	if sp.Kind != Shared {
		return true, nil
	}
	doc, ok, err := s.memberDoc(ctx, spaceID)
	if err != nil || !ok {
		return err == nil, err
	}
	return doc.CanWrite(s.accountID), nil
}

func (s *Store) memberDoc(ctx context.Context, spaceID string) (space.MemberDoc, bool, error) {
	var (
		doc space.MemberDoc
		ok  bool
	)
	err := s.do(ctx, func() error {
		var err error
		doc, ok, err = s.st.LatestMemberDoc(spaceID)
		return err
	})
	return doc, ok, err
}

// Links returns the space ids that a search scoped to spaceID should also
// consult.
//
// A link is a retrieval hint and never an access grant: it can name a space
// this store does not hold, and reading one is only possible if it is
// present locally. Filter the result through GetSpace before searching it.
func (s *Store) Links(ctx context.Context, spaceID string) ([]string, error) {
	if spaceID == "" {
		return nil, invalid("spaceID is required")
	}
	var ids []string
	err := s.do(ctx, func() error {
		var err error
		ids, err = s.st.Links(spaceID)
		return err
	})
	return ids, err
}
