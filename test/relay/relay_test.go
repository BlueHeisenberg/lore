// Package relaytest holds integration tests for the lore relay: full HTTP
// flows over httptest, exactly as a client device would drive them.
package relaytest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BlueHeisenberg/lore/internal/relay"
)

// device is a test client: one keypair acting as an enrolled device.
type device struct {
	t       *testing.T
	baseURL string
	pub     string
	priv    ed25519.PrivateKey
}

func newDevice(t *testing.T, baseURL string) *device {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &device{t: t, baseURL: baseURL, pub: hex.EncodeToString(pub), priv: priv}
}

func (d *device) challenge() string {
	d.t.Helper()
	body, _ := json.Marshal(map[string]string{"device_pub": d.pub})
	resp, err := http.Post(d.baseURL+"/v1/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		d.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		d.t.Fatal(err)
	}
	return out.Nonce
}

// do runs the challenge + signed-request flow. path may include a query
// string; the signature covers the bare path (protocol contract).
func (d *device) do(method, path string, body []byte) *http.Response {
	d.t.Helper()
	nonce := d.challenge()
	urlPath := path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		urlPath = path[:i]
	}
	sum := sha256.Sum256(body)
	msg := append([]byte(nonce+method+urlPath), sum[:]...)
	sig := ed25519.Sign(d.priv, msg)
	req, err := http.NewRequest(method, d.baseURL+path, bytes.NewReader(body))
	if err != nil {
		d.t.Fatal(err)
	}
	req.Header.Set("X-Lore-Device", d.pub)
	req.Header.Set("X-Lore-Nonce", nonce)
	req.Header.Set("X-Lore-Sig", hex.EncodeToString(sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.t.Fatal(err)
	}
	return resp
}

func (d *device) must(method, path string, body []byte, want int) []byte {
	d.t.Helper()
	resp := d.do(method, path, body)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		d.t.Fatalf("%s %s = %d, want %d (body: %s)", method, path, resp.StatusCode, want, b)
	}
	return b
}

// account is a test account key that can enroll devices.
type account struct {
	pub  string
	priv ed25519.PrivateKey
}

func newAccount(t *testing.T) *account {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &account{pub: hex.EncodeToString(pub), priv: priv}
}

func (a *account) enroll(d *device) {
	d.t.Helper()
	sig := ed25519.Sign(a.priv, []byte("lore-enroll"+d.pub))
	body, _ := json.Marshal(map[string]string{
		"account_pub": a.pub,
		"device_pub":  d.pub,
		"cert":        "integration-test",
		"account_sig": hex.EncodeToString(sig),
	})
	d.must("POST", "/v1/devices", body, http.StatusOK)
}

func startRelay(t *testing.T) (string, string) {
	t.Helper()
	dataDir := t.TempDir()
	srv, err := relay.NewServer(relay.Config{Addr: ":0", DataDir: dataDir, QuotaMB: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts.URL, dataDir
}

type logItem struct {
	Seq  int64  `json:"seq"`
	Data string `json:"data"`
}

// TestSharedSpaceFlow: two accounts, owner registers + grants, both append,
// both read the same log, seq is contiguous, revocation cuts access.
func TestSharedSpaceFlow(t *testing.T) {
	url, _ := startRelay(t)
	owner, member := newAccount(t), newAccount(t)
	odev, mdev := newDevice(t, url), newDevice(t, url)
	owner.enroll(odev)
	member.enroll(mdev)

	space := strings.Repeat("s", 64) // hex-shaped blinded id
	body, _ := json.Marshal(map[string]string{"blinded_id": space})
	odev.must("POST", "/v1/spaces", body, http.StatusOK)

	// Member has no access before the grant.
	mdev.must("POST", "/v1/spaces/"+space+"/log", []byte("delta-x"), http.StatusForbidden)

	gb, _ := json.Marshal(map[string]string{"account_pub": member.pub})
	odev.must("POST", "/v1/spaces/"+space+"/grant", gb, http.StatusOK)

	// Owner appends 1, member appends 2 — seqs are contiguous.
	var got struct {
		Seq int64 `json:"seq"`
	}
	json.Unmarshal(odev.must("POST", "/v1/spaces/"+space+"/log", []byte("delta-1"), http.StatusOK), &got)
	if got.Seq != 1 {
		t.Fatalf("first seq = %d, want 1", got.Seq)
	}
	json.Unmarshal(mdev.must("POST", "/v1/spaces/"+space+"/log", []byte("delta-2"), http.StatusOK), &got)
	if got.Seq != 2 {
		t.Fatalf("second seq = %d, want 2", got.Seq)
	}

	// Member reads from 1 and sees both, byte-identical.
	var items []logItem
	json.Unmarshal(mdev.must("GET", "/v1/spaces/"+space+"/log?from=1", nil, http.StatusOK), &items)
	if len(items) != 2 || items[0].Seq != 1 || items[1].Seq != 2 {
		t.Fatalf("read log = %+v", items)
	}
	d1, _ := base64.StdEncoding.DecodeString(items[0].Data)
	if string(d1) != "delta-1" {
		t.Fatalf("delta 1 = %q", d1)
	}

	// from=2 skips the first.
	json.Unmarshal(mdev.must("GET", "/v1/spaces/"+space+"/log?from=2", nil, http.StatusOK), &items)
	if len(items) != 1 || items[0].Seq != 2 {
		t.Fatalf("from=2 = %+v", items)
	}

	// Revoke: member loses read and append.
	odev.must("DELETE", "/v1/spaces/"+space+"/grant/"+member.pub, nil, http.StatusNoContent)
	mdev.must("GET", "/v1/spaces/"+space+"/log?from=1", nil, http.StatusForbidden)
	mdev.must("POST", "/v1/spaces/"+space+"/log", []byte("nope"), http.StatusForbidden)
}

// TestLongPollWakeup: a reader long-polls on an empty offset while a second
// goroutine appends; the reader must wake with the delta well before the
// wait deadline.
func TestLongPollWakeup(t *testing.T) {
	url, _ := startRelay(t)
	acc := newAccount(t)
	writer, reader := newDevice(t, url), newDevice(t, url)
	acc.enroll(writer)
	acc.enroll(reader)

	space := strings.Repeat("p", 32)
	body, _ := json.Marshal(map[string]string{"blinded_id": space})
	writer.must("POST", "/v1/spaces", body, http.StatusOK)

	// Immediate read with wait=0 and nothing to read: 204.
	reader.must("GET", "/v1/spaces/"+space+"/log?from=1&wait=0", nil, http.StatusNoContent)

	var wg sync.WaitGroup
	wg.Add(1)
	var items []logItem
	var elapsed time.Duration
	go func() {
		defer wg.Done()
		start := time.Now()
		b := reader.must("GET", "/v1/spaces/"+space+"/log?from=1&wait=20", nil, http.StatusOK)
		elapsed = time.Since(start)
		json.Unmarshal(b, &items)
	}()

	time.Sleep(300 * time.Millisecond) // let the poller park
	writer.must("POST", "/v1/spaces/"+space+"/log", []byte("wake-up"), http.StatusOK)
	wg.Wait()

	if len(items) != 1 || items[0].Seq != 1 {
		t.Fatalf("long-poll items = %+v", items)
	}
	if elapsed >= 20*time.Second {
		t.Fatalf("long-poll did not wake early (took %v)", elapsed)
	}
	got, _ := base64.StdEncoding.DecodeString(items[0].Data)
	if string(got) != "wake-up" {
		t.Fatalf("long-poll data = %q", got)
	}
}

// TestSnapshotCompaction: PUT snapshot?upto=N drops log rows and blob files
// with seq<=N; GET snapshot returns bytes + X-Lore-Upto; seq keeps counting
// past the compacted prefix.
func TestSnapshotCompaction(t *testing.T) {
	url, dataDir := startRelay(t)
	acc := newAccount(t)
	dev := newDevice(t, url)
	acc.enroll(dev)

	space := strings.Repeat("q", 32)
	body, _ := json.Marshal(map[string]string{"blinded_id": space})
	dev.must("POST", "/v1/spaces", body, http.StatusOK)

	// No snapshot yet: 404.
	dev.must("GET", "/v1/spaces/"+space+"/snapshot", nil, http.StatusNotFound)

	for i := 1; i <= 3; i++ {
		dev.must("POST", "/v1/spaces/"+space+"/log", []byte("delta"), http.StatusOK)
	}
	logDir := filepath.Join(dataDir, "data", space, "log")
	for _, seq := range []string{"1", "2", "3"} {
		if _, err := os.Stat(filepath.Join(logDir, seq)); err != nil {
			t.Fatalf("log blob %s missing before compaction: %v", seq, err)
		}
	}

	snap := []byte("compacted-encrypted-state-upto-2")
	dev.must("PUT", "/v1/spaces/"+space+"/snapshot?upto=2", snap, http.StatusOK)

	// Prefix blobs deleted, tail kept.
	for _, seq := range []string{"1", "2"} {
		if _, err := os.Stat(filepath.Join(logDir, seq)); !os.IsNotExist(err) {
			t.Fatalf("log blob %s not deleted by compaction", seq)
		}
	}
	if _, err := os.Stat(filepath.Join(logDir, "3")); err != nil {
		t.Fatalf("log blob 3 wrongly deleted: %v", err)
	}

	// Snapshot readable with the right upto header.
	resp := dev.do("GET", "/v1/spaces/"+space+"/snapshot", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get snapshot status %d", resp.StatusCode)
	}
	if h := resp.Header.Get("X-Lore-Upto"); h != "2" {
		t.Fatalf("X-Lore-Upto = %q, want 2", h)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, snap) {
		t.Fatal("snapshot bytes mismatch")
	}

	// Log read from 1 now returns only seq 3.
	var items []logItem
	json.Unmarshal(dev.must("GET", "/v1/spaces/"+space+"/log?from=1", nil, http.StatusOK), &items)
	if len(items) != 1 || items[0].Seq != 3 {
		t.Fatalf("post-compaction log = %+v", items)
	}

	// Sequence numbering continues after compaction (even if the whole log
	// was folded): compact upto=3, then append -> seq 4.
	dev.must("PUT", "/v1/spaces/"+space+"/snapshot?upto=3", []byte("snap-3"), http.StatusOK)
	var got4 struct {
		Seq int64 `json:"seq"`
	}
	json.Unmarshal(dev.must("POST", "/v1/spaces/"+space+"/log", []byte("delta-4"), http.StatusOK), &got4)
	if got4.Seq != 4 {
		t.Fatalf("post-full-compaction seq = %d, want 4", got4.Seq)
	}
}

// TestFreshLoginKeyboxFlow: the recovery path — enroll on device A, store
// keybox + claim handle; a brand-new client with NO device fetches the
// keybox by handle unauthenticated, then enrolls a second device.
func TestFreshLoginKeyboxFlow(t *testing.T) {
	url, _ := startRelay(t)
	acc := newAccount(t)
	devA := newDevice(t, url)
	acc.enroll(devA)

	keybox := []byte("wrapped-under-argon2id(passphrase+recovery)")
	devA.must("PUT", "/v1/account/keybox", keybox, http.StatusNoContent)
	hb, _ := json.Marshal(map[string]string{"handle": "fresh-login"})
	devA.must("POST", "/v1/account/handle", hb, http.StatusOK)

	// Fresh machine: no device key enrolled, only the handle known.
	resp, err := http.Get(url + "/v1/accounts/fresh-login/keybox")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(got, keybox) {
		t.Fatalf("fresh keybox fetch: status %d", resp.StatusCode)
	}

	// After local unwrap the client holds the account key: enroll device B
	// and read the authed keybox route too.
	devB := newDevice(t, url)
	acc.enroll(devB)
	if got := devB.must("GET", "/v1/account/keybox", nil, http.StatusOK); !bytes.Equal(got, keybox) {
		t.Fatal("device B keybox mismatch")
	}
}
