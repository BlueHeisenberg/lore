package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func inviteAddr(c byte) string { return strings.Repeat(string(c), 32) }

func createInviteBody(t *testing.T, addr string, blob []byte, expiresInS int64, maxUses int) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"addr": addr, "blob": base64.StdEncoding.EncodeToString(blob),
		"expires_in_s": expiresInS, "max_uses": maxUses,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func claimBody(t *testing.T, claim []byte) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"claim": base64.StdEncoding.EncodeToString(claim)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInviteCreateFetchClaimLifecycle(t *testing.T) {
	s, ts := newTestServer(t, 100)
	owner, odev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, owner, odev)
	joiner, jdev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, joiner, jdev)

	addr := inviteAddr('a')
	blob := []byte("opaque-encrypted-invite-payload")

	// Unenrolled/unauthenticated create is rejected.
	resp, err := http.Post(ts.URL+"/v1/invites", "application/json",
		bytes.NewReader(createInviteBody(t, addr, blob, 0, 0)))
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, resp, http.StatusUnauthorized)

	// Create with defaults (expires_in_s=0 -> 6h, max_uses=0 -> 1).
	resp = signedDo(t, ts.URL, odev, "POST", "/v1/invites", createInviteBody(t, addr, blob, 0, 0))
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create invite: %d %s", resp.StatusCode, b)
	}
	var created struct {
		Addr      string `json:"addr"`
		ExpiresAt int64  `json:"expires_at"`
		MaxUses   int    `json:"max_uses"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.MaxUses != 1 {
		t.Fatalf("default max_uses = %d, want 1", created.MaxUses)
	}
	slack := created.ExpiresAt - time.Now().Unix()
	if slack < inviteMaxExpiry-60 || slack > inviteMaxExpiry+60 {
		t.Fatalf("default expiry %ds from now, want ~%d", slack, inviteMaxExpiry)
	}

	// Duplicate addr conflicts.
	mustStatus(t, signedDo(t, ts.URL, odev, "POST", "/v1/invites",
		createInviteBody(t, addr, blob, 0, 0)), http.StatusConflict)

	// Unauthenticated GET returns the blob verbatim.
	r2, err := http.Get(ts.URL + "/v1/invites/" + addr)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK || !bytes.Equal(got, blob) {
		t.Fatalf("get invite = %d %q", r2.StatusCode, got)
	}

	// Unknown address 404s.
	r3, _ := http.Get(ts.URL + "/v1/invites/" + inviteAddr('b'))
	mustStatus(t, r3, http.StatusNotFound)

	// Joiner (authed) parks a claim; owner lists it; a stranger sees none.
	claim := []byte("opaque-encrypted-claim")
	mustStatus(t, signedDo(t, ts.URL, jdev, "POST", "/v1/invites/"+addr+"/claims",
		claimBody(t, claim)), http.StatusOK)

	listClaims := func(dev keypair) []struct {
		ID        int64  `json:"id"`
		Addr      string `json:"addr"`
		Claim     string `json:"claim"`
		CreatedAt int64  `json:"created_at"`
	} {
		resp := signedDo(t, ts.URL, dev, "GET", "/v1/invites/claims", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list claims: %d", resp.StatusCode)
		}
		var items []struct {
			ID        int64  `json:"id"`
			Addr      string `json:"addr"`
			Claim     string `json:"claim"`
			CreatedAt int64  `json:"created_at"`
		}
		json.NewDecoder(resp.Body).Decode(&items)
		return items
	}
	items := listClaims(odev)
	if len(items) != 1 || items[0].Addr != addr {
		t.Fatalf("owner claims = %+v", items)
	}
	if b, _ := base64.StdEncoding.DecodeString(items[0].Claim); !bytes.Equal(b, claim) {
		t.Fatal("claim bytes corrupted")
	}
	if len(listClaims(jdev)) != 0 {
		t.Fatal("non-owner must not see claims")
	}

	// Exhaustion: single-use invite is now used up — GET 404s, claims 409.
	r4, _ := http.Get(ts.URL + "/v1/invites/" + addr)
	mustStatus(t, r4, http.StatusNotFound)
	mustStatus(t, signedDo(t, ts.URL, jdev, "POST", "/v1/invites/"+addr+"/claims",
		claimBody(t, claim)), http.StatusConflict)

	// Only the owner can mark processed; ids-scoped deletion works.
	body, _ := json.Marshal(map[string]any{"ids": []int64{items[0].ID}})
	mustStatus(t, signedDo(t, ts.URL, jdev, "POST", "/v1/invites/"+addr+"/processed", body),
		http.StatusForbidden)
	mustStatus(t, signedDo(t, ts.URL, odev, "POST", "/v1/invites/"+addr+"/processed", body),
		http.StatusNoContent)
	if len(listClaims(odev)) != 0 {
		t.Fatal("processed claim still listed")
	}

	// Revoke: only owner; then everything is gone.
	mustStatus(t, signedDo(t, ts.URL, jdev, "DELETE", "/v1/invites/"+addr, nil), http.StatusForbidden)
	mustStatus(t, signedDo(t, ts.URL, odev, "DELETE", "/v1/invites/"+addr, nil), http.StatusNoContent)
	if _, err := s.Store().GetInvite(addr); err == nil {
		t.Fatal("revoked invite still in store")
	}
	r5, _ := http.Get(ts.URL + "/v1/invites/" + addr)
	mustStatus(t, r5, http.StatusNotFound)
}

func TestInviteClamps(t *testing.T) {
	_, ts := newTestServer(t, 100)
	owner, odev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, owner, odev)

	// expires_in_s and max_uses above the caps are clamped.
	resp := signedDo(t, ts.URL, odev, "POST", "/v1/invites",
		createInviteBody(t, inviteAddr('c'), []byte("x"), 999999, 99))
	var created struct {
		ExpiresAt int64 `json:"expires_at"`
		MaxUses   int   `json:"max_uses"`
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.MaxUses != inviteMaxUses {
		t.Fatalf("max_uses = %d, want clamp %d", created.MaxUses, inviteMaxUses)
	}
	if slack := created.ExpiresAt - time.Now().Unix(); slack > inviteMaxExpiry+60 {
		t.Fatalf("expiry %ds exceeds the 6h clamp", slack)
	}

	// Values below the clamps pass through (the tests' 1s-expiry knob).
	resp = signedDo(t, ts.URL, odev, "POST", "/v1/invites",
		createInviteBody(t, inviteAddr('d'), []byte("x"), 1, 2))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create short-lived: %d", resp.StatusCode)
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if slack := created.ExpiresAt - time.Now().Unix(); slack > 2 {
		t.Fatalf("1s expiry not honored: %ds", slack)
	}

	// Bad addr / empty blob rejected.
	mustStatus(t, signedDo(t, ts.URL, odev, "POST", "/v1/invites",
		createInviteBody(t, "NOT-HEX", []byte("x"), 0, 0)), http.StatusBadRequest)
	b, _ := json.Marshal(map[string]any{"addr": inviteAddr('e'), "blob": ""})
	mustStatus(t, signedDo(t, ts.URL, odev, "POST", "/v1/invites", b), http.StatusBadRequest)
}

func TestInviteExpiryAndSweep(t *testing.T) {
	s, ts := newTestServer(t, 100)
	owner, odev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, owner, odev)
	joiner, jdev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, joiner, jdev)

	addr := inviteAddr('f')
	resp := signedDo(t, ts.URL, odev, "POST", "/v1/invites",
		createInviteBody(t, addr, []byte("x"), 1, 5))
	mustStatus(t, resp, http.StatusOK)

	time.Sleep(1100 * time.Millisecond)

	// Expired: GET 404, claim 404.
	r, _ := http.Get(ts.URL + "/v1/invites/" + addr)
	mustStatus(t, r, http.StatusNotFound)
	mustStatus(t, signedDo(t, ts.URL, jdev, "POST", "/v1/invites/"+addr+"/claims",
		claimBody(t, []byte("y"))), http.StatusNotFound)

	// The sweep removes the row entirely.
	if err := s.Store().SweepInvites(time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store().GetInvite(addr); err == nil {
		t.Fatal("expired invite survived the sweep")
	}
}

func TestInviteGetRateLimit(t *testing.T) {
	_, ts := newTestServer(t, 100)
	// 10/min/IP on the open GET: the 11th request must be rejected.
	for i := 0; i < 10; i++ {
		resp, err := http.Get(ts.URL + "/v1/invites/" + inviteAddr('9'))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d rate-limited early", i+1)
		}
	}
	resp, err := http.Get(ts.URL + "/v1/invites/" + inviteAddr('9'))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("11th request status = %d, want 429", resp.StatusCode)
	}
}

func TestInviteOpenQuota(t *testing.T) {
	_, ts := newTestServer(t, 100)
	owner, odev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, owner, odev)

	for i := 0; i < inviteMaxOpen; i++ {
		addr := fmt.Sprintf("%032x", i+1)
		mustStatus(t, signedDo(t, ts.URL, odev, "POST", "/v1/invites",
			createInviteBody(t, addr, []byte("x"), 3600, 1)), http.StatusOK)
	}
	mustStatus(t, signedDo(t, ts.URL, odev, "POST", "/v1/invites",
		createInviteBody(t, fmt.Sprintf("%032x", 999), []byte("x"), 3600, 1)),
		http.StatusForbidden)
}
