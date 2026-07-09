package relay

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Invite links (docs/IMPLEMENTATION.md §Relay, "Invite links"): the relay is
// a dumb mailbox. The owner parks an OPAQUE encrypted payload at an address
// derived from the bearer secret; joiners fetch it (unauthenticated — the
// address is unguessable and possessing it implies possessing the secret)
// and park opaque encrypted claims back. The relay never sees the secret,
// the space, or any key material.

// Invite policy caps.
const (
	inviteMaxExpiry  = 21600 // 6h, seconds — expires_in_s is clamped to this
	inviteMaxUses    = 10    // max_uses clamp
	inviteMaxOpen    = 20    // open invites per owner account
	inviteMaxBlob    = 64 << 10
	inviteSweepEvery = time.Minute
)

// inviteAddrRe pins the address grammar: hex(HMAC)[:32].
var inviteAddrRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidInviteAddr reports whether s is acceptable as an invite address.
func ValidInviteAddr(s string) bool { return inviteAddrRe.MatchString(s) }

// --- store ---

// Invite is a row of invites.
type Invite struct {
	Addr         string
	OwnerAccount string
	Blob         []byte
	ExpiresAt    int64
	MaxUses      int
	Uses         int
	CreatedAt    int64
}

// InviteClaim is a row of invite_claims.
type InviteClaim struct {
	ID        int64
	Addr      string
	Claim     []byte
	CreatedAt int64
}

// CreateInvite parks a blob at addr for ownerAccount. The addr is a PK: a
// collision (astronomically unlikely between honest tokens) is a conflict.
// Enforces the per-account open-invite quota.
func (st *Store) CreateInvite(addr, ownerAccount string, blob []byte, expiresAt int64, maxUses int) error {
	now := time.Now().Unix()
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var open int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM invites WHERE owner_account=? AND expires_at>?`,
		ownerAccount, now).Scan(&open); err != nil {
		return err
	}
	if open >= inviteMaxOpen {
		return fmt.Errorf("%w: at most %d open invites per account", ErrPlanPolicy, inviteMaxOpen)
	}
	if _, err := tx.Exec(`INSERT INTO invites(addr,owner_account,blob,expires_at,max_uses,uses,created_at)
		VALUES(?,?,?,?,?,0,?)`, addr, ownerAccount, blob, expiresAt, maxUses, now); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "constraint") {
			return fmt.Errorf("%w: invite address already in use", ErrConflict)
		}
		return err
	}
	return tx.Commit()
}

// GetInvite returns the invite row. ErrNotFound if absent.
func (st *Store) GetInvite(addr string) (*Invite, error) {
	var inv Invite
	err := st.db.QueryRow(`SELECT addr,owner_account,blob,expires_at,max_uses,uses,created_at
		FROM invites WHERE addr=?`, addr).
		Scan(&inv.Addr, &inv.OwnerAccount, &inv.Blob, &inv.ExpiresAt, &inv.MaxUses, &inv.Uses, &inv.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// AddInviteClaim appends a claim and counts it against uses, atomically.
// ErrNotFound when the invite is missing or expired; ErrConflict when
// exhausted (uses >= max_uses).
func (st *Store) AddInviteClaim(addr string, claim []byte) error {
	now := time.Now().Unix()
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expiresAt int64
	var maxUses, uses int
	err = tx.QueryRow(`SELECT expires_at,max_uses,uses FROM invites WHERE addr=?`, addr).
		Scan(&expiresAt, &maxUses, &uses)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && expiresAt <= now) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if uses >= maxUses {
		return fmt.Errorf("%w: invite exhausted", ErrConflict)
	}
	if _, err := tx.Exec(`INSERT INTO invite_claims(addr,claim,created_at) VALUES(?,?,?)`,
		addr, claim, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE invites SET uses=uses+1 WHERE addr=?`, addr); err != nil {
		return err
	}
	return tx.Commit()
}

// InviteClaimsForOwner returns every pending claim on invites owned by the
// account, oldest first.
func (st *Store) InviteClaimsForOwner(ownerAccount string) ([]InviteClaim, error) {
	rows, err := st.db.Query(`SELECT c.id, c.addr, c.claim, c.created_at
		FROM invite_claims c JOIN invites i ON i.addr = c.addr
		WHERE i.owner_account=? ORDER BY c.id`, ownerAccount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InviteClaim
	for rows.Next() {
		var c InviteClaim
		if err := rows.Scan(&c.ID, &c.Addr, &c.Claim, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteInviteClaims removes processed claim rows for addr. Empty ids =
// everything currently parked at the address.
func (st *Store) DeleteInviteClaims(addr string, ids []int64) error {
	if len(ids) == 0 {
		_, err := st.db.Exec(`DELETE FROM invite_claims WHERE addr=?`, addr)
		return err
	}
	for _, id := range ids {
		if _, err := st.db.Exec(`DELETE FROM invite_claims WHERE addr=? AND id=?`, addr, id); err != nil {
			return err
		}
	}
	return nil
}

// DeleteInvite revokes an invite and drops its claims.
func (st *Store) DeleteInvite(addr string) error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM invite_claims WHERE addr=?`, addr); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM invites WHERE addr=?`, addr); err != nil {
		return err
	}
	return tx.Commit()
}

// SweepInvites drops expired invites and their claims.
func (st *Store) SweepInvites(now int64) error {
	_, err := st.db.Exec(`DELETE FROM invite_claims WHERE addr IN
		(SELECT addr FROM invites WHERE expires_at<=?)`, now)
	if err != nil {
		return err
	}
	_, err = st.db.Exec(`DELETE FROM invites WHERE expires_at<=?`, now)
	return err
}

// maybeSweepInvites runs the expiry sweep at most once per inviteSweepEvery.
// Hooked from handleChallenge — every authed client mints challenges, so the
// sweep piggybacks on normal traffic like the nonce sweep does.
func (s *Server) maybeSweepInvites() {
	now := time.Now()
	s.inviteSweepMu.Lock()
	due := now.Sub(s.lastInviteSweep) >= inviteSweepEvery
	if due {
		s.lastInviteSweep = now
	}
	s.inviteSweepMu.Unlock()
	if due {
		if err := s.store.SweepInvites(now.Unix()); err != nil {
			s.logger.Printf("invite sweep: %v", err)
		}
	}
}

// --- handlers ---

// handleCreateInvite: POST /v1/invites (authed)
// {addr, blob (b64), expires_in_s, max_uses} -> {addr, expires_at}.
// expires_in_s defaults to and is clamped at 6h; max_uses defaults to 1,
// clamped at 10. Values BELOW the clamps pass through (tests mint 1s ones).
func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	var req struct {
		Addr       string `json:"addr"`
		Blob       string `json:"blob"`
		ExpiresInS int64  `json:"expires_in_s"`
		MaxUses    int    `json:"max_uses"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !ValidInviteAddr(req.Addr) {
		httpError(w, http.StatusBadRequest, "addr must be 32 lowercase hex chars")
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Blob)
	if err != nil || len(blob) == 0 {
		httpError(w, http.StatusBadRequest, "blob must be non-empty base64")
		return
	}
	if len(blob) > inviteMaxBlob {
		httpError(w, http.StatusRequestEntityTooLarge, "invite blob exceeds 64 KB cap")
		return
	}
	expires := req.ExpiresInS
	if expires <= 0 || expires > inviteMaxExpiry {
		expires = inviteMaxExpiry
	}
	uses := req.MaxUses
	if uses <= 0 {
		uses = 1
	}
	if uses > inviteMaxUses {
		uses = inviteMaxUses
	}
	expiresAt := time.Now().Unix() + expires
	if err := s.store.CreateInvite(req.Addr, a.accountPub, blob, expiresAt, uses); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"addr": req.Addr, "expires_at": expiresAt, "max_uses": uses})
}

// handleGetInvite: GET /v1/invites/{addr} — UNAUTHENTICATED by design: the
// address derives from the bearer secret, so possessing it implies
// possessing the secret; the blob is useless without the secret's key
// anyway. Rate-limited 10/min/IP against blind address scanning.
func (s *Server) handleGetInvite(w http.ResponseWriter, r *http.Request) {
	if !s.inviteLimiter.allow(clientIP(r)) {
		httpError(w, http.StatusTooManyRequests, "rate limit: 10/min")
		return
	}
	addr := r.PathValue("addr")
	if !ValidInviteAddr(addr) {
		httpError(w, http.StatusBadRequest, "invalid invite address")
		return
	}
	inv, err := s.store.GetInvite(addr)
	if err != nil {
		storeError(w, err)
		return
	}
	if inv.ExpiresAt <= time.Now().Unix() || inv.Uses >= inv.MaxUses {
		httpError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(inv.Blob)
}

// handlePostInviteClaim: POST /v1/invites/{addr}/claims (authed — the joiner
// self-enrolled its device first) {claim (b64)}.
func (s *Server) handlePostInviteClaim(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	addr := r.PathValue("addr")
	if !ValidInviteAddr(addr) {
		httpError(w, http.StatusBadRequest, "invalid invite address")
		return
	}
	var req struct {
		Claim string `json:"claim"`
	}
	if err := json.Unmarshal(a.body, &req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	claim, err := base64.StdEncoding.DecodeString(req.Claim)
	if err != nil || len(claim) == 0 {
		httpError(w, http.StatusBadRequest, "claim must be non-empty base64")
		return
	}
	if len(claim) > inviteMaxBlob {
		httpError(w, http.StatusRequestEntityTooLarge, "claim exceeds 64 KB cap")
		return
	}
	if err := s.store.AddInviteClaim(addr, claim); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"addr": addr})
}

// handleListInviteClaims: GET /v1/invites/claims (authed) — pending claims
// on every invite owned by the caller's account.
func (s *Server) handleListInviteClaims(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	claims, err := s.store.InviteClaimsForOwner(a.accountPub)
	if err != nil {
		storeError(w, err)
		return
	}
	type item struct {
		ID        int64  `json:"id"`
		Addr      string `json:"addr"`
		Claim     string `json:"claim"` // base64
		CreatedAt int64  `json:"created_at"`
	}
	items := make([]item, len(claims))
	for i, c := range claims {
		items[i] = item{ID: c.ID, Addr: c.Addr,
			Claim: base64.StdEncoding.EncodeToString(c.Claim), CreatedAt: c.CreatedAt}
	}
	writeJSON(w, http.StatusOK, items)
}

// requireInviteOwner resolves {addr} and checks the caller owns the invite.
func (s *Server) requireInviteOwner(w http.ResponseWriter, r *http.Request, a *authedRequest) (string, bool) {
	addr := r.PathValue("addr")
	if !ValidInviteAddr(addr) {
		httpError(w, http.StatusBadRequest, "invalid invite address")
		return "", false
	}
	inv, err := s.store.GetInvite(addr)
	if err != nil {
		storeError(w, err)
		return "", false
	}
	if inv.OwnerAccount != a.accountPub {
		httpError(w, http.StatusForbidden, "only the invite owner may manage it")
		return "", false
	}
	return addr, true
}

// handleInviteProcessed: POST /v1/invites/{addr}/processed (authed, owner)
// {ids: [..]} — delete the processed claim rows (empty ids = all).
func (s *Server) handleInviteProcessed(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	addr, ok := s.requireInviteOwner(w, r, a)
	if !ok {
		return
	}
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if len(a.body) > 0 {
		if err := json.Unmarshal(a.body, &req); err != nil {
			httpError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	if err := s.store.DeleteInviteClaims(addr, req.IDs); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeInvite: DELETE /v1/invites/{addr} (authed, owner).
func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request, a *authedRequest) {
	addr, ok := s.requireInviteOwner(w, r, a)
	if !ok {
		return
	}
	if err := s.store.DeleteInvite(addr); err != nil {
		storeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
