package syncproto

import (
	"database/sql"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// MemberCheck decides whether an entry's author may write into a space.
// It runs on the receive path after the signature check.
type MemberCheck func(sp store.Space, e store.Entry) error

// DefaultMemberCheck is the Phase-3 rule (personal-space account gate only;
// shared spaces accept any key holder).
//
// Deprecated: superseded by MemberDocCheck, which additionally requires the
// author to be a writer/owner in the latest verified member doc. Kept only
// until internal/relayclient's ApplyDelta migrates (it has the *sql.DB at
// hand); every other receive path uses MemberDocCheck.
func DefaultMemberCheck(ownAccount string) MemberCheck {
	return func(sp store.Space, e store.Entry) error {
		if sp.Kind == "personal" && e.AuthorAccount != ownAccount {
			return fmt.Errorf("personal space rejects foreign author %s", e.AuthorAccount)
		}
		return nil
	}
}

// MemberDocCheck is the Phase-4 membership rule for the receive path
// (replaces the Phase-3 DefaultMemberCheck):
//   - personal space: only our own account writes (same-account devices);
//   - shared space: the entry's author must hold the writer or owner role
//     in the LATEST VERIFIED member doc of the space. A shared space with
//     no verified member doc accepts nothing — docs travel in the same
//     sync/push message ahead of entries, so an honest peer is never stuck.
func MemberDocCheck(db *sql.DB, ownAccount string) MemberCheck {
	return func(sp store.Space, e store.Entry) error {
		if sp.Kind == "personal" {
			if e.AuthorAccount != ownAccount {
				return fmt.Errorf("personal space rejects foreign author %s", e.AuthorAccount)
			}
			return nil
		}
		raws, err := RawMemberDocs(db, sp.SpaceID)
		if err != nil {
			return err
		}
		doc, ok := space.LatestDoc(sp.SpaceID, raws)
		if !ok {
			return fmt.Errorf("shared space %s has no verified member list; rejecting remote entries", sp.SpaceID)
		}
		switch doc.Role(e.AuthorAccount) {
		case space.RoleOwner, space.RoleWriter:
			return nil
		case space.RoleReader:
			return fmt.Errorf("author %s is a reader in space %s (member list v%d); write rejected",
				e.AuthorAccount, sp.SpaceID, doc.Version)
		default:
			return fmt.Errorf("author %s is not a member of space %s (member list v%d)",
				e.AuthorAccount, sp.SpaceID, doc.Version)
		}
	}
}

// ApplyEntries is the verified receive path shared by pull and push:
// for each entry it (1) checks the entry belongs to the resolved space,
// (2) verifies the origin device's Ed25519 signature over the canonical
// encoding, (3) runs the membership check, then (4) applies under LWW
// (store.ApplyRemote). Entries that lose LWW are skipped silently; entries
// failing verification abort the batch. Returns how many were applied.
//
// Note on the device->account chain: the transport layer has already proven
// the *sender* controls a device of senderAccount (TLS key + device cert
// header). Entries relayed from other devices verify against their
// origin_device pubkey, and the member check pins author_account to the
// verified member list; the origin_device -> author_account binding itself
// is not yet carried in member docs (pinned contract shape) — a residual
// gap only exploitable by an already-invited writer.
func ApplyEntries(st *store.Store, sp store.Space, entries []store.Entry, check MemberCheck) (int, error) {
	applied := 0
	for _, e := range entries {
		if e.SpaceID != sp.SpaceID {
			return applied, fmt.Errorf("entry %s targets space %s, expected %s", e.EntryID, e.SpaceID, sp.SpaceID)
		}
		if err := store.VerifyEntry(e, e.OriginDevice); err != nil {
			return applied, fmt.Errorf("entry %s: %w", e.EntryID, err)
		}
		if check != nil {
			if err := check(sp, e); err != nil {
				return applied, fmt.Errorf("entry %s: %w", e.EntryID, err)
			}
		}
		ok, err := st.ApplyRemote(e)
		if err != nil {
			return applied, err
		}
		if ok {
			applied++
		}
	}
	return applied, nil
}
