package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestHMAC(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func nowUnix() int64     { return time.Now().Unix() }
func nowTime() time.Time { return time.Now() }

// --- test harness ---

func newTestServer(t *testing.T, quotaMB int64) (*Server, *httptest.Server) {
	t.Helper()
	cfg := Config{Addr: ":0", DataDir: t.TempDir(), QuotaMB: quotaMB}
	s, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })
	return s, ts
}

type keypair struct {
	pub  string
	priv ed25519.PrivateKey
}

func newKeypair(t *testing.T) keypair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return keypair{pub: hex.EncodeToString(pub), priv: priv}
}

// challenge fetches a nonce for the device.
func challengeFor(t *testing.T, baseURL, devicePub string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"device_pub": devicePub})
	resp, err := http.Post(baseURL+"/v1/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status %d", resp.StatusCode)
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("challenge decode: %v", err)
	}
	return out.Nonce
}

// signedDo performs the full challenge + signed request flow as a device.
func signedDo(t *testing.T, baseURL string, dev keypair, method, path string, body []byte) *http.Response {
	t.Helper()
	nonce := challengeFor(t, baseURL, dev.pub)
	return signedDoWithNonce(t, baseURL, dev, nonce, method, path, body)
}

func signedDoWithNonce(t *testing.T, baseURL string, dev keypair, nonce, method, path string, body []byte) *http.Response {
	t.Helper()
	urlPath := path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		urlPath = path[:i]
	}
	sig := ed25519.Sign(dev.priv, authMessage(nonce, method, urlPath, body))
	req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Lore-Device", dev.pub)
	req.Header.Set("X-Lore-Nonce", nonce)
	req.Header.Set("X-Lore-Sig", hex.EncodeToString(sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	return resp
}

// enroll self-enrolls a device under an account.
func enroll(t *testing.T, baseURL string, account, device keypair) {
	t.Helper()
	resp := enrollResp(t, baseURL, account, device)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll status %d: %s", resp.StatusCode, b)
	}
}

func enrollResp(t *testing.T, baseURL string, account, device keypair) *http.Response {
	t.Helper()
	accountSig := ed25519.Sign(account.priv, []byte(enrollPrefix+device.pub))
	body, _ := json.Marshal(map[string]string{
		"account_pub": account.pub,
		"device_pub":  device.pub,
		"cert":        "test-cert",
		"account_sig": hex.EncodeToString(accountSig),
	})
	return signedDo(t, baseURL, device, "POST", "/v1/devices", body)
}

func mustStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (body: %s)", resp.StatusCode, want, b)
	}
}

// --- auth flow ---

func TestChallengeAuthFlow(t *testing.T) {
	s, ts := newTestServer(t, 100)
	account, device := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, account, device)

	// Sanity: enrolled device makes an authed call.
	body, _ := json.Marshal(map[string]string{"blinded_id": strings.Repeat("a", 32)})
	mustStatus(t, signedDo(t, ts.URL, device, "POST", "/v1/spaces", body), http.StatusOK)

	// Bad signature (signed by a different key) is rejected.
	imposter := keypair{pub: device.pub, priv: newKeypair(t).priv}
	mustStatus(t, signedDo(t, ts.URL, imposter, "POST", "/v1/spaces", body), http.StatusUnauthorized)

	// Tampered body is rejected.
	nonce := challengeFor(t, ts.URL, device.pub)
	sig := ed25519.Sign(device.priv, authMessage(nonce, "POST", "/v1/spaces", body))
	req, _ := http.NewRequest("POST", ts.URL+"/v1/spaces", strings.NewReader(`{"blinded_id":"tampered_tampered"}`))
	req.Header.Set("X-Lore-Device", device.pub)
	req.Header.Set("X-Lore-Nonce", nonce)
	req.Header.Set("X-Lore-Sig", hex.EncodeToString(sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, resp, http.StatusUnauthorized)

	// Unenrolled device with valid signature is rejected on authed routes.
	stranger := newKeypair(t)
	mustStatus(t, signedDo(t, ts.URL, stranger, "POST", "/v1/spaces", body), http.StatusUnauthorized)

	// Missing headers rejected.
	resp, err = http.Post(ts.URL+"/v1/spaces", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, resp, http.StatusUnauthorized)
	_ = s
}

func TestNonceSingleUse(t *testing.T) {
	_, ts := newTestServer(t, 100)
	account, device := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, account, device)

	body, _ := json.Marshal(map[string]string{"blinded_id": strings.Repeat("b", 32)})
	nonce := challengeFor(t, ts.URL, device.pub)
	mustStatus(t, signedDoWithNonce(t, ts.URL, device, nonce, "POST", "/v1/spaces", body), http.StatusOK)
	// Replaying the same nonce (even with a valid signature) fails.
	mustStatus(t, signedDoWithNonce(t, ts.URL, device, nonce, "POST", "/v1/spaces", body), http.StatusUnauthorized)
	// A nonce issued to one device cannot be redeemed by another.
	other := newKeypair(t)
	enroll(t, ts.URL, account, other)
	n2 := challengeFor(t, ts.URL, device.pub)
	mustStatus(t, signedDoWithNonce(t, ts.URL, other, n2, "POST", "/v1/spaces", body), http.StatusUnauthorized)
}

func TestDeviceSelfEnroll(t *testing.T) {
	s, ts := newTestServer(t, 100)
	account, device := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, account, device)

	// Account was auto-created with plan 'trial'.
	acct, err := s.Store().GetAccount(account.pub)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if acct.Plan != "trial" {
		t.Fatalf("plan = %q, want trial", acct.Plan)
	}
	// Idempotent re-enroll.
	enroll(t, ts.URL, account, device)

	// Bad account_sig rejected.
	dev2, evil := newKeypair(t), newKeypair(t)
	badSig := ed25519.Sign(evil.priv, []byte(enrollPrefix+dev2.pub))
	body, _ := json.Marshal(map[string]string{
		"account_pub": account.pub, "device_pub": dev2.pub,
		"cert": "", "account_sig": hex.EncodeToString(badSig),
	})
	mustStatus(t, signedDo(t, ts.URL, dev2, "POST", "/v1/devices", body), http.StatusUnauthorized)

	// A device cannot re-enroll under a different account.
	account2 := newKeypair(t)
	mustStatus(t, enrollResp(t, ts.URL, account2, device), http.StatusConflict)
}

// --- keybox & handle ---

func TestKeyboxRoundtripAndHandleFetch(t *testing.T) {
	_, ts := newTestServer(t, 100)
	account, device := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, account, device)

	keybox := []byte("argon2id-wrapped-account-key-opaque-bytes")
	mustStatus(t, signedDo(t, ts.URL, device, "PUT", "/v1/account/keybox", keybox), http.StatusNoContent)

	resp := signedDo(t, ts.URL, device, "GET", "/v1/account/keybox", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get keybox status %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, keybox) {
		t.Fatalf("keybox roundtrip mismatch")
	}

	// Claim a handle, then fetch keybox UNAUTHENTICATED by handle (fresh login).
	hb, _ := json.Marshal(map[string]string{"handle": "david-test"})
	mustStatus(t, signedDo(t, ts.URL, device, "POST", "/v1/account/handle", hb), http.StatusOK)

	r2, err := http.Get(ts.URL + "/v1/accounts/david-test/keybox")
	if err != nil {
		t.Fatal(err)
	}
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("unauth keybox status %d", r2.StatusCode)
	}
	got2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if !bytes.Equal(got2, keybox) {
		t.Fatalf("unauth keybox mismatch")
	}

	// Handle resolution for invites.
	r3, err := http.Get(ts.URL + "/v1/accounts/david-test")
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		AccountPub string `json:"account_pub"`
	}
	json.NewDecoder(r3.Body).Decode(&res)
	r3.Body.Close()
	if res.AccountPub != account.pub {
		t.Fatalf("handle resolve = %q, want %q", res.AccountPub, account.pub)
	}

	// Duplicate handle claim by another account conflicts.
	acc2, dev2 := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, acc2, dev2)
	mustStatus(t, signedDo(t, ts.URL, dev2, "POST", "/v1/account/handle", hb), http.StatusConflict)
}

func TestHandleKeyboxRateLimit(t *testing.T) {
	_, ts := newTestServer(t, 100)
	// 5/min/IP: the 6th request must be rejected regardless of handle validity.
	for i := 0; i < 5; i++ {
		resp, err := http.Get(ts.URL + "/v1/accounts/no-such-handle/keybox")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d rate-limited early", i+1)
		}
	}
	resp, err := http.Get(ts.URL + "/v1/accounts/no-such-handle/keybox")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th request status = %d, want 429", resp.StatusCode)
	}
}

// --- quotas & plan policy ---

func TestQuotaRejection(t *testing.T) {
	_, ts := newTestServer(t, 1) // 1 MB quota
	account, device := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, account, device)

	space := strings.Repeat("c", 32)
	body, _ := json.Marshal(map[string]string{"blinded_id": space})
	mustStatus(t, signedDo(t, ts.URL, device, "POST", "/v1/spaces", body), http.StatusOK)

	big := bytes.Repeat([]byte{0x42}, 700<<10) // 700 KB
	mustStatus(t, signedDo(t, ts.URL, device, "POST", "/v1/spaces/"+space+"/log", big), http.StatusOK)
	// Second 700 KB append exceeds the 1 MB account quota.
	mustStatus(t, signedDo(t, ts.URL, device, "POST", "/v1/spaces/"+space+"/log", big),
		http.StatusInsufficientStorage)
}

func TestFreePlanSpacePolicy(t *testing.T) {
	s, ts := newTestServer(t, 100)
	owner, dev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, owner, dev)
	if err := s.Store().SetPlan(owner.pub, "free"); err != nil {
		t.Fatal(err)
	}
	// Two collaborator accounts.
	collab1, cdev1 := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, collab1, cdev1)
	collab2, cdev2 := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, collab2, cdev2)

	sp := func(c byte) string { return strings.Repeat(string(c), 32) }
	reg := func(id string) *http.Response {
		b, _ := json.Marshal(map[string]string{"blinded_id": id})
		return signedDo(t, ts.URL, dev, "POST", "/v1/spaces", b)
	}
	// Free: 2 owned spaces OK (personal + shared), 3rd rejected.
	mustStatus(t, reg(sp('d')), http.StatusOK)
	mustStatus(t, reg(sp('e')), http.StatusOK)
	mustStatus(t, reg(sp('f')), http.StatusForbidden)
	// Idempotent re-register of an existing space still OK.
	mustStatus(t, reg(sp('d')), http.StatusOK)

	grant := func(id, who string) *http.Response {
		b, _ := json.Marshal(map[string]string{"account_pub": who})
		return signedDo(t, ts.URL, dev, "POST", "/v1/spaces/"+id+"/grant", b)
	}
	// One collaborator on one space OK; a second collaborator there rejected;
	// sharing a second space rejected.
	mustStatus(t, grant(sp('e'), collab1.pub), http.StatusOK)
	mustStatus(t, grant(sp('e'), collab1.pub), http.StatusOK) // idempotent
	mustStatus(t, grant(sp('e'), collab2.pub), http.StatusForbidden)
	mustStatus(t, grant(sp('d'), collab1.pub), http.StatusForbidden)

	// Paid plan lifts both limits.
	if err := s.Store().SetPlan(owner.pub, "paid"); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, reg(sp('f')), http.StatusOK)
	mustStatus(t, grant(sp('e'), collab2.pub), http.StatusOK)

	// Non-owner cannot grant.
	b, _ := json.Marshal(map[string]string{"account_pub": collab2.pub})
	mustStatus(t, signedDo(t, ts.URL, cdev1, "POST", "/v1/spaces/"+sp('e')+"/grant", b),
		http.StatusForbidden)
}

// --- access control on log ---

func TestLogAccessControl(t *testing.T) {
	_, ts := newTestServer(t, 100)
	owner, dev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, owner, dev)
	outsider, odev := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, outsider, odev)

	space := strings.Repeat("g", 32)
	body, _ := json.Marshal(map[string]string{"blinded_id": space})
	mustStatus(t, signedDo(t, ts.URL, dev, "POST", "/v1/spaces", body), http.StatusOK)

	mustStatus(t, signedDo(t, ts.URL, odev, "POST", "/v1/spaces/"+space+"/log", []byte("x")),
		http.StatusForbidden)
	mustStatus(t, signedDo(t, ts.URL, odev, "GET", "/v1/spaces/"+space+"/log?from=1", nil),
		http.StatusForbidden)
	// Unknown space 404s.
	mustStatus(t, signedDo(t, ts.URL, dev, "GET", "/v1/spaces/"+strings.Repeat("z", 32)+"/log", nil),
		http.StatusNotFound)
}

// --- stripe ---

func stripeSign(t *testing.T, secret string, ts int64, body []byte) string {
	t.Helper()
	mac := newTestHMAC(secret, fmt.Sprintf("%d.%s", ts, body))
	return fmt.Sprintf("t=%d,v1=%s", ts, mac)
}

func TestStripeWebhook(t *testing.T) {
	const secret = "whsec_test_secret"
	dataDir := t.TempDir()
	cfg := Config{Addr: ":0", DataDir: dataDir, QuotaMB: 100, StripeWebhookSecret: secret}
	s, err := NewServer(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close() })

	account, device := newKeypair(t), newKeypair(t)
	enroll(t, ts.URL, account, device)

	post := func(sigHeader string, body []byte) *http.Response {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/stripe/webhook", bytes.NewReader(body))
		req.Header.Set("Stripe-Signature", sigHeader)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	now := nowUnix()

	// checkout.session.completed -> paid + customer stored.
	body := []byte(`{"type":"checkout.session.completed","data":{"object":{"customer":"cus_123","metadata":{"account_pub":"` + account.pub + `"}}}}`)
	mustStatus(t, post(stripeSign(t, secret, now, body), body), http.StatusOK)
	acct, _ := s.Store().GetAccount(account.pub)
	if acct.Plan != "paid" || acct.StripeCustomer != "cus_123" {
		t.Fatalf("after checkout: plan=%q customer=%q", acct.Plan, acct.StripeCustomer)
	}

	// subscription.updated with non-active status -> free (via customer id).
	body = []byte(`{"type":"customer.subscription.updated","data":{"object":{"customer":"cus_123","status":"past_due"}}}`)
	mustStatus(t, post(stripeSign(t, secret, now, body), body), http.StatusOK)
	if acct, _ = s.Store().GetAccount(account.pub); acct.Plan != "free" {
		t.Fatalf("after past_due: plan=%q, want free", acct.Plan)
	}

	// subscription.updated active -> paid again.
	body = []byte(`{"type":"customer.subscription.updated","data":{"object":{"customer":"cus_123","status":"active"}}}`)
	mustStatus(t, post(stripeSign(t, secret, now, body), body), http.StatusOK)
	if acct, _ = s.Store().GetAccount(account.pub); acct.Plan != "paid" {
		t.Fatalf("after active: plan=%q, want paid", acct.Plan)
	}

	// subscription.deleted -> free.
	body = []byte(`{"type":"customer.subscription.deleted","data":{"object":{"customer":"cus_123"}}}`)
	mustStatus(t, post(stripeSign(t, secret, now, body), body), http.StatusOK)
	if acct, _ = s.Store().GetAccount(account.pub); acct.Plan != "free" {
		t.Fatalf("after deleted: plan=%q, want free", acct.Plan)
	}

	// Wrong signature rejected.
	body = []byte(`{"type":"customer.subscription.deleted","data":{"object":{"customer":"cus_123"}}}`)
	mustStatus(t, post(stripeSign(t, "wrong_secret", now, body), body), http.StatusBadRequest)

	// Stale timestamp rejected (10 minutes old).
	mustStatus(t, post(stripeSign(t, secret, now-600, body), body), http.StatusBadRequest)

	// Missing header rejected.
	mustStatus(t, post("", body), http.StatusBadRequest)
}

func TestStripeWebhookDisabled(t *testing.T) {
	_, ts := newTestServer(t, 100) // no STRIPE_WEBHOOK_SECRET
	resp, err := http.Post(ts.URL+"/v1/stripe/webhook", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, resp, http.StatusServiceUnavailable)
}

func TestVerifyStripeSignatureUnit(t *testing.T) {
	body := []byte(`{"id":"evt_1"}`)
	const secret = "whsec_abc"
	now := nowTime()
	ts := now.Unix()
	good := stripeSign(t, secret, ts, body)

	if err := verifyStripeSignature(good, body, secret, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Multiple v1 candidates: one bogus + one good passes.
	multi := fmt.Sprintf("t=%d,v1=%s,v1=%s", ts, strings.Repeat("00", 32),
		strings.Split(good, "v1=")[1])
	if err := verifyStripeSignature(multi, body, secret, now); err != nil {
		t.Fatalf("multi-candidate rejected: %v", err)
	}
	if err := verifyStripeSignature(good, []byte("tampered"), secret, now); err == nil {
		t.Fatal("tampered body accepted")
	}
	if err := verifyStripeSignature(good, body, "other", now); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if err := verifyStripeSignature("v1=deadbeef", body, secret, now); err == nil {
		t.Fatal("missing t= accepted")
	}
}
