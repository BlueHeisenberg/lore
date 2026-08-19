package lore

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

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
	sp, err := s.st.CreateSharedSpace("", name, "", account.EncPub, priv)
	if err != nil {
		return Space{}, wrap(err)
	}
	return spaceOf(sp), nil
}

// CreateSpaceWithID creates a shared space at an id the caller already holds,
// and returns the existing one unchanged when that id is already here.
//
// It is CreateSpace for the caller that decided the id first. The case it
// exists for is a store that does not exist yet when the id is chosen: a
// setup wizard mints an id, writes it into a configuration file, and the
// process that will actually hold the space — a container on a volume nothing
// outside it can reach — boots later and has to arrive at that id rather than
// mint a second one and ask a human to copy it back.
//
// # Idempotent, so a caller may call it on every boot
//
// A second call with an id this store already holds writes nothing and
// returns the space that is there. That is the whole point: the caller does
// not have to know whether this is a first boot, and there is no state to
// keep to find out. name is not compared, because Space.Name is a local
// display name and never identity — an id that is already here is the space
// the caller asked for, whatever either of them calls it. Nothing is renamed
// either: this call does not exist to edit a space it did not create.
//
// The kind IS compared. A space's kind decides whether it can hold another
// account's writes at all — a personal space rejects every foreign author, on
// every path, forever — so returning one where a shared space was asked for
// would hand back something the caller cannot use for what it asked. That is
// ErrSpaceExists.
//
// # What it refuses
//
// A malformed id is ErrInvalidArgument and is never coerced into a valid one.
// The id must be a UUID in canonical text — 36 characters, lowercase hex,
// four hyphens, no braces and no urn: prefix — because it is a primary key
// and two spellings of one UUID are two rows.
//
// A name another space in this store already holds is ErrSpaceExists, exactly
// as in CreateSpace, unless that other space IS this id. A caller whose id
// changed but whose name did not is a configuration that has moved a member's
// memory somewhere else, and it is worth stopping on.
//
// kind must be Shared and name may not be "personal": the personal space is
// Init's, one per home, and it is not something a caller may add a second of
// under an id of its choosing.
//
// A read-only store cannot own anything: ErrReadOnly.
//
// # On accepting an id from outside
//
// Space ids are global in lore's model, so it is fair to ask what a caller
// could do by choosing one. The answer is nothing, and the reason is that an
// id is not what two stores match on. Peers intersect blinded ids —
// HMAC(space_key, "lore-blind" || space_id) — and the space key here is
// freshly generated and never leaves this home. Two unrelated stores that
// create "the same" space id therefore compute different blinded ids, never
// recognise each other's space, and exchange nothing; the id alone carries no
// authority, and a space still arrives from someone else only through the
// invite and join handshake, where the key travels wrapped to a member.
//
// What a shared id does NOT survive is that handshake: joining a space whose
// id this store already holds overwrites the local row, key included, because
// enrolment and restore must reproduce a space verbatim. So do not create a
// space at an id you also expect to be invited into. For a space that lives
// in one store and is shared with nobody — which is the case this call was
// added for — there is no such handshake and nothing to collide with.
func (s *Store) CreateSpaceWithID(ctx context.Context, id, name string, kind SpaceKind) (Space, error) {
	if err := validSpaceID(id); err != nil {
		return Space{}, err
	}
	switch {
	case name == "":
		return Space{}, invalid("name is required")
	case name == "personal":
		return Space{}, invalid(`the name "personal" is reserved for the personal space`)
	case kind != Shared:
		return Space{}, invalid("kind must be %q; the personal space is created by Init", Shared)
	}
	// This lookup is also the closed-store and context check: it runs before
	// anything is written and reports both.
	switch existing, err := s.GetSpace(ctx, id); {
	case err == nil:
		if existing.Kind != kind {
			return Space{}, fmt.Errorf("%w: %s is already a %s space here", ErrSpaceExists, id, existing.Kind)
		}
		return existing, nil
	case !errors.Is(err, ErrSpaceNotFound):
		return Space{}, err
	}
	switch other, err := s.SpaceByName(ctx, name); {
	case err == nil:
		return Space{}, fmt.Errorf("%w: %q is space %s, not %s", ErrSpaceExists, name, other.ID, id)
	case !errors.Is(err, ErrSpaceNotFound):
		return Space{}, err
	}
	// Loaded here and held nowhere, for the reason CreateSpace gives.
	account, err := keys.LoadAccount(s.home)
	if err != nil {
		return Space{}, err
	}
	priv, err := account.SigningKey()
	if err != nil {
		return Space{}, err
	}
	sp, err := s.st.CreateSharedSpace(id, name, "", account.EncPub, priv)
	if err != nil {
		return Space{}, wrap(err)
	}
	return spaceOf(sp), nil
}

// validSpaceID accepts a UUID in canonical text and nothing else. uuid.Parse
// alone is not the check: it also reads braced, urn: and unhyphenated forms,
// and each of those would insert a second row for one UUID.
func validSpaceID(id string) error {
	if id == "" {
		return invalid("id is required")
	}
	u, err := uuid.Parse(id)
	if err != nil || u.String() != id {
		return invalid("id must be a UUID in canonical form (lowercase, hyphenated, no braces): %q", id)
	}
	return nil
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
