package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTrialExpiry: a 'trial' account older than TrialDays is policy-treated
// as 'free' (max 2 owned spaces) even though the row still says trial.
func TestTrialExpiry(t *testing.T) {
	cfg := Config{Addr: ":0", DataDir: t.TempDir(), QuotaMB: 100, TrialDays: 30}
	s, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })

	account, device := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, account, device)

	mkSpace := func(id string) *http.Response {
		body, _ := json.Marshal(map[string]string{"blinded_id": strings.Repeat(id, 32)})
		return signedDo(t, ts.URL, device, "POST", "/v1/spaces", body)
	}

	// Fresh trial: three spaces are fine (trial = byte quota only).
	for _, id := range []string{"a", "b", "c"} {
		mustStatus(t, mkSpace(id), http.StatusOK)
	}

	// Backdate the account past the trial window.
	if _, err := s.store.db.Exec(`UPDATE accounts SET created_at=? WHERE account_pub=?`,
		time.Now().Add(-31*24*time.Hour).Unix(), account.pub); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	// Lapsed trial behaves as free: already at >2 owned spaces, so a new one is refused.
	mustStatus(t, mkSpace("d"), http.StatusForbidden)

	// Admin/Stripe path restores it.
	if err := s.store.SetPlan(account.pub, "paid"); err != nil {
		t.Fatalf("SetPlan: %v", err)
	}
	mustStatus(t, mkSpace("d"), http.StatusOK)
}
