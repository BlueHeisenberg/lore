package relay

import (
	"fmt"
	"time"
)

// policyAction names the write being attempted, for plan gating.
type policyAction int

const (
	actionCreateSpace policyAction = iota // POST /v1/spaces (new space row)
	actionGrant                           // POST /v1/spaces/{id}/grant
	actionStoreBytes                      // log append / snapshot / keybox byte growth
)

// checkPolicy is THE entitlement policy, kept in one place because it will be
// tuned. Current rules (docs/RELAY.md "free tier = one shared space, one
// collaborator", adapted for local/dev where the personal space also relays):
//
//   - Byte quota (all plans): stored bytes per account — sum of log blob
//     sizes + snapshot sizes + keybox, attributed to the OWNER of each
//     space — must stay within LORE_RELAY_QUOTA_MB (default 100 MB).
//   - plan "free": may OWN at most 2 spaces total (1 personal + 1 shared),
//     and at most ONE owned space may have more than 1 access grant, with
//     at most 2 accounts holding access on it (owner + 1 collaborator).
//     Personal-space relaying is deliberately NOT restricted here so
//     local/dev setups work on the free plan.
//   - plan "trial" / "paid": unlimited spaces and grants within byte quota.
//
// ownerAccount is the account being charged (the space owner for space
// writes; the account itself for keybox writes). addBytes is the net byte
// growth of the attempted write (0 for pure metadata actions). blindedID is
// the target space for actionGrant (ignored otherwise).
func (s *Server) checkPolicy(ownerAccount string, action policyAction, blindedID string, addBytes int64) error {
	acct, err := s.store.GetAccount(ownerAccount)
	if err != nil {
		return err
	}

	// Byte quota applies to every plan.
	if addBytes > 0 {
		used, err := s.store.UsedBytes(ownerAccount)
		if err != nil {
			return err
		}
		if used+addBytes > s.quotaBytes {
			return fmt.Errorf("%w: %d + %d bytes exceeds quota %d",
				ErrQuotaExceeded, used, addBytes, s.quotaBytes)
		}
	}

	// Effective plan: a trial lapses into free after TrialDays (default 30,
	// per docs/RELAY.md "one month free trial"). The row keeps saying 'trial'
	// — only Stripe or the admin CLI rewrite plans — but policy stops honoring
	// it. TrialDays=0 disables expiry (dev/self-hosted relays).
	plan := acct.Plan
	if plan == "trial" && s.cfg.TrialDays > 0 &&
		time.Now().Unix()-acct.CreatedAt > s.cfg.TrialDays*86400 {
		plan = "free"
	}
	if plan != "free" {
		return nil // trial/paid: byte quota only
	}

	switch action {
	case actionCreateSpace:
		var owned int
		if err := s.store.db.QueryRow(
			`SELECT COUNT(*) FROM spaces WHERE owner_account=?`, ownerAccount).Scan(&owned); err != nil {
			return err
		}
		if owned >= 2 {
			return fmt.Errorf("%w: free plan allows at most 2 owned spaces (1 personal + 1 shared)", ErrPlanPolicy)
		}
	case actionGrant:
		// After this grant, the target space must have <= 2 access holders,
		// and it must be the only owned space with > 1 holder.
		var holders int
		if err := s.store.db.QueryRow(
			`SELECT COUNT(*) FROM space_access WHERE blinded_id=?`, blindedID).Scan(&holders); err != nil {
			return err
		}
		if holders >= 2 {
			return fmt.Errorf("%w: free plan allows at most 1 collaborator on the shared space", ErrPlanPolicy)
		}
		var otherShared int
		if err := s.store.db.QueryRow(
			`SELECT COUNT(*) FROM spaces sp WHERE sp.owner_account=? AND sp.blinded_id<>?
			 AND (SELECT COUNT(*) FROM space_access sa WHERE sa.blinded_id=sp.blinded_id) > 1`,
			ownerAccount, blindedID).Scan(&otherShared); err != nil {
			return err
		}
		if otherShared > 0 {
			return fmt.Errorf("%w: free plan allows at most 1 shared space", ErrPlanPolicy)
		}
	case actionStoreBytes:
		// byte quota already enforced above; free plan has no extra byte rule
	}
	return nil
}
