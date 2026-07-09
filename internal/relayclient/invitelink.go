package relayclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/BlueHeisenberg/lore/internal/invite"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// Invite-link flows shared by cmd/lore and the integration tests: the OWNER
// mints an async bearer token (MintInvite), the JOINER redeems it any time
// before expiry (JoinInvite). The relay hosts only ciphertext at a
// secret-derived address; the owner's daemon (internal/daemon claim loop)
// completes the membership asynchronously.

// Invite-link limits mirrored client-side (the relay clamps regardless).
const (
	InviteMaxExpiry = 6 * time.Hour
	InviteMaxUses   = 10
)

// MintInvite mints an invite link for sp: generates the token, parks the
// encrypted payload on the relay, and records the secret locally so this
// device's daemon can verify and admit claims. The caller's account must be
// an owner of the (shared) space per its latest verified member doc.
// expiresIn <= 0 defaults to 6h; both limits are validated here and clamped
// again server-side.
func MintInvite(ctx context.Context, home string, st *store.Store, sp store.Space,
	role string, expiresIn time.Duration, maxUses int) (invite.Token, error) {

	if sp.Kind != "shared" {
		return invite.Token{}, store.ErrPersonalSpace
	}
	if role != space.RoleWriter && role != space.RoleReader {
		return invite.Token{}, fmt.Errorf("invite role must be writer or reader, got %q", role)
	}
	if expiresIn <= 0 {
		expiresIn = InviteMaxExpiry
	}
	if expiresIn > InviteMaxExpiry {
		return invite.Token{}, fmt.Errorf("invite expiry %s exceeds the 6h maximum", expiresIn)
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if maxUses > InviteMaxUses {
		return invite.Token{}, fmt.Errorf("invite uses %d exceeds the maximum of %d", maxUses, InviteMaxUses)
	}
	if len(sp.SpaceKey) != 32 {
		return invite.Token{}, fmt.Errorf("space %q has no usable space key", sp.Name)
	}
	relayURL := RelayURL(home)
	if relayURL == "" {
		return invite.Token{}, ErrNoRelay
	}
	account, err := keys.LoadAccount(home)
	if err != nil {
		return invite.Token{}, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return invite.Token{}, err
	}
	// Fail fast: only an owner can later sign the member-doc evolution.
	latest, ok, err := st.LatestMemberDoc(sp.SpaceID)
	if err != nil {
		return invite.Token{}, err
	}
	if !ok {
		return invite.Token{}, fmt.Errorf("space %s has no verified member list", sp.Name)
	}
	if latest.Role(account.AccountID()) != space.RoleOwner {
		return invite.Token{}, fmt.Errorf("only an owner can invite; this account is %q in space %s",
			latest.Role(account.AccountID()), sp.Name)
	}

	c, err := New(relayURL, device)
	if err != nil {
		return invite.Token{}, err
	}
	if err := c.EnrollDevice(ctx, account); err != nil {
		return invite.Token{}, fmt.Errorf("enroll device with relay: %w", err)
	}

	tok, err := invite.NewToken()
	if err != nil {
		return invite.Token{}, err
	}
	blob, err := invite.SealPayload(tok, invite.Payload{
		SpaceID:      sp.SpaceID,
		SpaceKey:     sp.SpaceKey,
		Kind:         sp.Kind,
		Name:         sp.Name,
		ProjectRef:   sp.ProjectRef,
		Role:         role,
		OwnerAccount: account.SignPub,
		OwnerEncPub:  account.EncPub,
	})
	if err != nil {
		return invite.Token{}, err
	}
	if err := c.CreateInvite(ctx, tok.Addr(), blob, expiresIn, maxUses); err != nil {
		return invite.Token{}, err
	}

	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return invite.Token{}, err
	}
	defer db.Close()
	now := time.Now().Unix()
	if err := SaveLocalInvite(db, LocalInvite{
		Addr:      tok.Addr(),
		SpaceID:   sp.SpaceID,
		Secret:    tok.String(),
		Role:      role,
		UsesLeft:  maxUses,
		ExpiresAt: now + int64(expiresIn/time.Second),
		CreatedAt: now,
	}); err != nil {
		// The relay row exists but we lost the secret record: revoke to avoid
		// an unredeemable orphan.
		_ = c.RevokeInvite(ctx, tok.Addr())
		return invite.Token{}, err
	}
	return tok, nil
}

// JoinLinkResult reports what JoinInvite accomplished.
type JoinLinkResult struct {
	SpaceID   string
	SpaceName string // local name (suffixed on collision)
	Role      string // from the member doc when confirmed, else the payload's
	Members   int    // members in the doc naming us (0 when pending)
	Pending   bool   // claim parked but the owner's daemon has not admitted us yet
}

// JoinInvite redeems an invite token: fetches and decrypts the payload,
// stores the space (key included), enrolls this device with the relay,
// parks the encrypted claim, and polls up to pollTimeout for the member doc
// naming this account to arrive through the normal relay pull. If the
// owner's daemon is offline the join still succeeds with Pending=true —
// membership completes once the owner's device comes online.
func JoinInvite(ctx context.Context, home, relayURL, tokenStr string,
	pollTimeout time.Duration) (JoinLinkResult, error) {

	tok, err := invite.ParseToken(tokenStr)
	if err != nil {
		return JoinLinkResult{}, err
	}
	if relayURL == "" {
		relayURL = RelayURL(home)
	}
	if relayURL == "" {
		return JoinLinkResult{}, ErrNoRelay
	}
	account, err := keys.LoadAccount(home)
	if err != nil {
		return JoinLinkResult{}, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return JoinLinkResult{}, err
	}

	blob, err := FetchInvite(ctx, relayURL, tok.Addr())
	if IsNotFound(err) {
		return JoinLinkResult{}, errors.New("invite not found — expired, revoked, already used, or mistyped")
	}
	if err != nil {
		return JoinLinkResult{}, err
	}
	payload, err := invite.OpenPayload(tok, blob)
	if err != nil {
		return JoinLinkResult{}, err
	}
	if payload.Kind != "shared" {
		return JoinLinkResult{}, fmt.Errorf("refusing invite to a %q space", payload.Kind)
	}
	if len(payload.SpaceKey) != 32 {
		return JoinLinkResult{}, errors.New("invite payload carries a malformed space key")
	}
	if payload.OwnerAccount == account.AccountID() {
		return JoinLinkResult{}, errors.New("this invite is from this same account — use `lore enroll` for new devices")
	}

	priv, err := device.PrivateKey()
	if err != nil {
		return JoinLinkResult{}, err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID: account.AccountID(), DeviceID: device.DeviceID(), DevicePriv: priv,
	})
	if err != nil {
		return JoinLinkResult{}, err
	}
	defer st.Close()
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return JoinLinkResult{}, err
	}
	defer db.Close()

	if _, err := st.GetSpace(payload.SpaceID); err == nil {
		return JoinLinkResult{}, fmt.Errorf("space %q already exists locally — already joined?", payload.Name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return JoinLinkResult{}, err
	}
	// Name collisions get a numeric suffix; the space id stays authoritative.
	name := payload.Name
	for i := 2; ; i++ {
		if _, err := st.SpaceByName(name); errors.Is(err, store.ErrNotFound) {
			break
		} else if err != nil {
			return JoinLinkResult{}, err
		}
		name = fmt.Sprintf("%s-%d", payload.Name, i)
	}
	if err := syncproto.InsertSpaceRecord(db, syncproto.SpaceRecord{
		SpaceID:    payload.SpaceID,
		Kind:       payload.Kind,
		Name:       name,
		ProjectRef: payload.ProjectRef,
		SpaceKey:   payload.SpaceKey,
		CreatedAt:  keys.Now(),
	}); err != nil {
		return JoinLinkResult{}, err
	}
	// Persist the relay so this device's daemon syncs the space (only when
	// none is configured yet — never silently switch relays).
	if RelayURL(home) == "" {
		if err := SetRelayURL(home, relayURL); err != nil {
			return JoinLinkResult{}, err
		}
	}

	c, err := New(relayURL, device)
	if err != nil {
		return JoinLinkResult{}, err
	}
	// Self-enroll is open: a joiner that never ran `lore signup` still gets a
	// relay account (plan 'trial') by proving its account key.
	if err := c.EnrollDevice(ctx, account); err != nil {
		return JoinLinkResult{}, fmt.Errorf("enroll device with relay: %w", err)
	}
	// Whoever touches the relay first registers the blinded space. If WE win
	// that race (the owner's daemon is offline), grant the owner access right
	// away — otherwise its runner would be locked out of the space it must
	// push the membership doc to. When the owner already registered it, the
	// conflict is the normal case and the owner grants US after the claim.
	blinded := syncproto.BlindSpaceID(payload.SpaceKey, payload.SpaceID)
	switch err := c.RegisterSpace(ctx, blinded); {
	case err == nil:
		if gerr := c.Grant(ctx, blinded, payload.OwnerAccount); gerr != nil && !IsConflict(gerr) {
			return JoinLinkResult{}, fmt.Errorf("grant the space owner relay access: %w", gerr)
		}
	case IsConflict(err):
		// registered by the owner (or another member) — proceed
	default:
		return JoinLinkResult{}, err
	}
	claim := invite.NewClaim(tok, account.SignPub, account.EncPub, account.EncPubSig, device.Name)
	sealed, err := invite.SealClaim(tok, claim)
	if err != nil {
		return JoinLinkResult{}, err
	}
	if err := c.PostInviteClaim(ctx, tok.Addr(), sealed); err != nil {
		return JoinLinkResult{}, err
	}
	pokeDaemonSync(home) // a running daemon rescans and starts the space loop

	res := JoinLinkResult{
		SpaceID: payload.SpaceID, SpaceName: name, Role: payload.Role, Pending: true,
	}
	sp := store.Space{
		SpaceID: payload.SpaceID, Kind: payload.Kind, Name: name,
		ProjectRef: payload.ProjectRef, SpaceKey: payload.SpaceKey,
	}
	deadline := time.Now().Add(pollTimeout)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		// Relay ACCESS arrives only when the owner's daemon grants it: poll
		// politely through 403s.
		_, _, err := PullSpace(ctx, c, st, db, sp, account.AccountID(), 3*time.Second)
		if err != nil && !IsForbidden(err) && !IsNotFound(err) {
			if errors.Is(err, ErrDeltaCorrupt) {
				return res, err
			}
			// transient (network, relay restart): keep polling
		}
		raws, derr := syncproto.RawMemberDocs(db, sp.SpaceID)
		if derr != nil {
			return res, derr
		}
		if doc, ok := space.LatestDoc(sp.SpaceID, raws); ok {
			if m, ok := doc.Member(account.AccountID()); ok {
				res.Role = m.Role
				res.Members = len(doc.Members)
				res.Pending = false
				return res, nil
			}
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return res, nil
}

// pokeDaemonSync fires POST /admin/sync at the local daemon if daemon.json
// exists — same fire-and-forget idiom as the MCP server's pokeDaemon.
func pokeDaemonSync(home string) {
	b, err := os.ReadFile(filepath.Join(home, "daemon.json"))
	if err != nil {
		return
	}
	var d struct {
		Port  int    `json:"port"`
		Token string `json:"token"`
	}
	if json.Unmarshal(b, &d) != nil || d.Port <= 0 {
		return
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/admin/sync?token=%s",
		d.Port, url.QueryEscape(d.Token)), "", nil)
	if err == nil {
		resp.Body.Close()
	}
}
