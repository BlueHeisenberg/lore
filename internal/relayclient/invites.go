package relayclient

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Typed client methods for the relay's invite-link routes plus the OWNER's
// local bookkeeping of open invites (kv rows in lore.db — the daemon needs
// the secret to decrypt and verify claims, and `lore space invites` lists
// them).

// CreateInvite parks an opaque invite blob at addr (authed).
// expiresIn <= 0 lets the server default (6h); the server clamps to 6h /
// 10 uses regardless.
func (c *Client) CreateInvite(ctx context.Context, addr string, blob []byte, expiresIn time.Duration, maxUses int) error {
	body, _ := json.Marshal(map[string]any{
		"addr":         addr,
		"blob":         base64.StdEncoding.EncodeToString(blob),
		"expires_in_s": int64(expiresIn / time.Second),
		"max_uses":     maxUses,
	})
	return c.doJSON(ctx, http.MethodPost, "/v1/invites", body, nil)
}

// FetchInvite fetches an invite blob by address. UNAUTHENTICATED by design
// (the joiner may not be enrolled yet; the address is secret-derived);
// rate-limited server-side to 10/min/IP. IsNotFound(err) covers missing,
// expired and exhausted invites alike.
func FetchInvite(ctx context.Context, baseURL, addr string) ([]byte, error) {
	resp, err := openGET(ctx, baseURL, "/v1/invites/"+addr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}
	return io.ReadAll(resp.Body)
}

// PostInviteClaim parks an opaque claim blob at an invite address (authed —
// the joiner self-enrolls its device first).
func (c *Client) PostInviteClaim(ctx context.Context, addr string, claim []byte) error {
	body, _ := json.Marshal(map[string]string{
		"claim": base64.StdEncoding.EncodeToString(claim),
	})
	return c.doJSON(ctx, http.MethodPost, "/v1/invites/"+addr+"/claims", body, nil)
}

// InviteClaim is one pending claim on an invite owned by this account.
type InviteClaim struct {
	ID        int64
	Addr      string
	Claim     []byte
	CreatedAt int64
}

// InviteClaims lists pending claims across every invite owned by the
// caller's account.
func (c *Client) InviteClaims(ctx context.Context) ([]InviteClaim, error) {
	var items []struct {
		ID        int64  `json:"id"`
		Addr      string `json:"addr"`
		Claim     string `json:"claim"`
		CreatedAt int64  `json:"created_at"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/invites/claims", nil, &items); err != nil {
		return nil, err
	}
	out := make([]InviteClaim, len(items))
	for i, it := range items {
		b, err := base64.StdEncoding.DecodeString(it.Claim)
		if err != nil {
			return nil, fmt.Errorf("relayclient: claim %d: %w", it.ID, err)
		}
		out[i] = InviteClaim{ID: it.ID, Addr: it.Addr, Claim: b, CreatedAt: it.CreatedAt}
	}
	return out, nil
}

// MarkClaimsProcessed deletes processed claim rows (owner only). Empty ids
// clears every claim currently parked at the address.
func (c *Client) MarkClaimsProcessed(ctx context.Context, addr string, ids []int64) error {
	body, _ := json.Marshal(map[string]any{"ids": ids})
	resp, err := c.do(ctx, http.MethodPost, "/v1/invites/"+addr+"/processed", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return readAPIError(resp)
	}
	return nil
}

// RevokeInvite deletes an invite and its claims (owner only).
func (c *Client) RevokeInvite(ctx context.Context, addr string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1/invites/"+addr, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return readAPIError(resp)
	}
	return nil
}

// --- owner-side local bookkeeping (kv rows, key "invite_local:<addr>") ---

const localInvitePrefix = "invite_local:"

// LocalInvite is the owner's record of an open invite link: enough to
// decrypt claims (Secret), admit the joiner (SpaceID, Role) and manage the
// invite (Addr, UsesLeft, ExpiresAt).
type LocalInvite struct {
	Addr      string `json:"addr"`
	SpaceID   string `json:"space_id"`
	Secret    string `json:"secret"` // canonical token string
	Role      string `json:"role"`
	UsesLeft  int    `json:"uses_left"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
	CreatedAt int64  `json:"created_at"`
}

// SaveLocalInvite upserts the invite's local record.
func SaveLocalInvite(db *sql.DB, li LocalInvite) error {
	b, err := json.Marshal(li)
	if err != nil {
		return err
	}
	return kvSet(db, localInvitePrefix+li.Addr, string(b))
}

// ListLocalInvites returns every locally-recorded invite, oldest first.
func ListLocalInvites(db *sql.DB) ([]LocalInvite, error) {
	rows, err := db.Query(`SELECT k, v FROM kv WHERE k LIKE ?`, localInvitePrefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LocalInvite
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		var li LocalInvite
		if err := json.Unmarshal([]byte(v), &li); err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out = append(out, li)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// kv has no ordering; sort by creation.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].CreatedAt < out[j-1].CreatedAt; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// DeleteLocalInvite removes the local record.
func DeleteLocalInvite(db *sql.DB, addr string) error {
	_, err := db.Exec(`DELETE FROM kv WHERE k=?`, localInvitePrefix+addr)
	return err
}

// FindLocalInvite resolves an address prefix (>= 6 chars) to exactly one
// local invite.
func FindLocalInvite(db *sql.DB, addrPrefix string) (LocalInvite, error) {
	if len(addrPrefix) < 6 {
		return LocalInvite{}, fmt.Errorf("address prefix %q too short (need >= 6 chars)", addrPrefix)
	}
	all, err := ListLocalInvites(db)
	if err != nil {
		return LocalInvite{}, err
	}
	var matches []LocalInvite
	for _, li := range all {
		if strings.HasPrefix(li.Addr, addrPrefix) {
			matches = append(matches, li)
		}
	}
	switch len(matches) {
	case 0:
		return LocalInvite{}, fmt.Errorf("no open invite matches %q", addrPrefix)
	case 1:
		return matches[0], nil
	default:
		return LocalInvite{}, fmt.Errorf("%q is ambiguous (%d matches)", addrPrefix, len(matches))
	}
}
