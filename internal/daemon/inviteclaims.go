// Invite-link claim processing — the owner-side half of the async invite
// flow (internal/invite + internal/relayclient/invitelink.go). Each relay
// manage pass, the runner fetches the encrypted claims parked on its open
// invites, verifies them against the locally-stored secrets, evolves the
// member doc exactly like the LAN invite does (shared admitMember helper),
// grants relay access, and pushes the new doc so the waiting joiner's pull
// completes.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/BlueHeisenberg/lore/internal/invite"
	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// errDiscardClaim wraps validation failures: the claim is junk (or already
// handled) and must be marked processed rather than retried forever.
var errDiscardClaim = errors.New("discard claim")

// processInviteClaims runs one claim round: called from managePass, so a
// transient relay error backs the whole pass off; per-claim validation
// failures are logged and discarded.
func (r *RelayRunner) processInviteClaims(ctx context.Context) error {
	locals, err := relayclient.ListLocalInvites(r.db)
	if err != nil {
		return err
	}
	if len(locals) == 0 {
		return nil
	}
	now := time.Now().Unix()
	byAddr := map[string]*relayclient.LocalInvite{}
	for i := range locals {
		li := &locals[i]
		if li.ExpiresAt <= now {
			_ = relayclient.DeleteLocalInvite(r.db, li.Addr) // relay sweeps its own row
			continue
		}
		byAddr[li.Addr] = li
	}
	if len(byAddr) == 0 {
		return nil
	}

	claims, err := r.client.InviteClaims(ctx)
	if err != nil {
		return fmt.Errorf("invite claims: %w", err)
	}
	for _, cl := range claims {
		li, ok := byAddr[cl.Addr]
		if !ok {
			continue // no local secret (revoked/expired here); expiry sweep clears it
		}
		err := r.processOneClaim(ctx, li, cl)
		switch {
		case err == nil, errors.Is(err, errDiscardClaim):
			if err != nil {
				r.logf("relay: invite claim on %s discarded: %v", shortID(cl.Addr), err)
			}
			if perr := r.client.MarkClaimsProcessed(ctx, cl.Addr, []int64{cl.ID}); perr != nil {
				return fmt.Errorf("mark claim processed: %w", perr)
			}
			if err == nil {
				li.UsesLeft--
				if li.UsesLeft <= 0 {
					// Single-use (or last use): remove the invite entirely.
					if rerr := r.client.RevokeInvite(ctx, li.Addr); rerr != nil && !relayclient.IsNotFound(rerr) {
						r.logf("relay: revoke used invite %s: %v", shortID(li.Addr), rerr)
					}
					_ = relayclient.DeleteLocalInvite(r.db, li.Addr)
					delete(byAddr, li.Addr)
				} else if serr := relayclient.SaveLocalInvite(r.db, *li); serr != nil {
					return serr
				}
			}
		default:
			// Transient (store/relay hiccup): leave the claim parked and let
			// the next pass retry.
			return fmt.Errorf("invite claim on %s: %w", shortID(cl.Addr), err)
		}
	}
	return nil
}

// processOneClaim verifies and admits a single claim. Returns nil on
// success, an errDiscardClaim-wrapped error for invalid/duplicate claims,
// or a bare error for transient failures worth retrying.
func (r *RelayRunner) processOneClaim(ctx context.Context, li *relayclient.LocalInvite,
	cl relayclient.InviteClaim) error {

	tok, err := invite.ParseToken(li.Secret)
	if err != nil {
		return fmt.Errorf("%w: local secret unusable: %v", errDiscardClaim, err)
	}
	// OpenClaim authenticates (AEAD under the token key) AND verifies the
	// token-keyed MAC binding the account pubkey.
	c, err := invite.OpenClaim(tok, cl.Claim)
	if err != nil {
		return fmt.Errorf("%w: %v", errDiscardClaim, err)
	}
	if err := verifyEncBinding(c.AccountPub, c.EncPub, c.EncPubSig); err != nil {
		return fmt.Errorf("%w: %v", errDiscardClaim, err)
	}
	if c.AccountPub == r.account.AccountID() {
		return fmt.Errorf("%w: claim from this same account (use `lore enroll` for new devices)", errDiscardClaim)
	}

	sp, err := r.st.GetSpace(li.SpaceID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: space %s no longer exists locally", errDiscardClaim, li.SpaceID)
	}
	if err != nil {
		return err
	}

	if _, err := admitMember(r.st, r.account, sp, c.AccountPub, c.EncPub, li.Role); err != nil {
		if errors.Is(err, errAlreadyMember) {
			// Duplicate claim: drop it without burning an invite use.
			return fmt.Errorf("%w: %v", errDiscardClaim, err)
		}
		return err
	}

	// Relay access + member-doc publication are best-effort here: a missed
	// grant is repaired by reconcileGrants every space-loop round, and the
	// docs also travel with the next entry push and every snapshot.
	blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)
	if err := r.client.RegisterSpace(ctx, blinded); err != nil && !relayclient.IsConflict(err) {
		r.logf("relay: register %s for invite doc push: %v", sp.Name, err)
	}
	if err := r.client.Grant(ctx, blinded, c.AccountPub); err != nil && !relayclient.IsConflict(err) {
		r.logf("relay: grant %s on %s: %v", shortID(c.AccountPub), sp.Name, err)
	}
	if err := r.pushMemberDocs(ctx, sp, blinded); err != nil {
		r.logf("relay: push member docs for %s: %v", sp.Name, err)
	}

	r.logf("invite claimed by %s — added to %s as %s", shortID(c.AccountPub), sp.Name, li.Role)
	return nil
}

// pushMemberDocs appends a doc-only delta so the joiner's pull sees the new
// member list immediately (PushSpace only fires when entries are pending).
func (r *RelayRunner) pushMemberDocs(ctx context.Context, sp store.Space, blinded string) error {
	docs, err := syncproto.MemberDocs(r.db, sp.SpaceID)
	if err != nil {
		return err
	}
	blob, err := relayclient.EncryptDelta(sp.SpaceKey, blinded, relayclient.Delta{MemberDocs: docs})
	if err != nil {
		return err
	}
	_, err = r.client.AppendLog(ctx, blinded, blob)
	return err
}
