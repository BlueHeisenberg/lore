package syncproto

import (
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/store"
)

// MemberCheck decides whether an entry's author may write into a space.
// It runs on the receive path after the signature check. Phase 4 replaces
// the default with full signed-member-doc verification; the hook shape is
// pinned here so that swap is local.
type MemberCheck func(sp store.Space, e store.Entry) error

// DefaultMemberCheck is the v1 rule:
//   - personal space: only our own account writes (same-account devices);
//   - shared space: any author holding the space key is accepted — possession
//     of the key implies an invite in v1. Phase 4 tightens this to "author is
//     a writer/owner in the latest verified member doc".
func DefaultMemberCheck(ownAccount string) MemberCheck {
	return func(sp store.Space, e store.Entry) error {
		if sp.Kind == "personal" && e.AuthorAccount != ownAccount {
			return fmt.Errorf("personal space rejects foreign author %s", e.AuthorAccount)
		}
		return nil
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
// header). Entries relayed from other devices of the same space verify
// against their origin_device pubkey; binding those devices to accounts is
// Phase 4's member-doc job (docs carry device certs), hence the hook.
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
