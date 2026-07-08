package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// challengeTTL is how long an issued nonce stays redeemable.
const challengeTTL = 60 * time.Second

// enrollPrefix is the domain-separation prefix for device enrollment
// signatures: account_sig = Ed25519(account_priv, "lore-enroll" || device_pub_hex).
const enrollPrefix = "lore-enroll"

type challenge struct {
	devicePub string
	expires   time.Time
}

// challenges is the in-memory single-use nonce store.
type challenges struct {
	mu sync.Mutex
	m  map[string]challenge // nonce hex -> challenge
}

func newChallenges() *challenges {
	return &challenges{m: make(map[string]challenge)}
}

// issue mints a random 32-byte nonce bound to devicePub, valid challengeTTL.
// Expired entries are swept opportunistically on every issue.
func (c *challenges) issue(devicePub string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b[:])
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[nonce] = challenge{devicePub: devicePub, expires: now.Add(challengeTTL)}
	return nonce, nil
}

// redeem consumes the nonce (single use). It must exist, be unexpired, and
// have been issued to the same device.
func (c *challenges) redeem(nonce, devicePub string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[nonce]
	if !ok {
		return false
	}
	delete(c.m, nonce) // single use, even on failure below
	return time.Now().Before(ch.expires) && ch.devicePub == devicePub
}

// authMessage builds the signed message for an authenticated request:
// nonce || method || path || SHA256(body). Nonce is the hex string as
// returned by /v1/challenge; path is the URL path WITHOUT the query string
// (replay across queries is prevented by the single-use nonce).
func authMessage(nonce, method, path string, body []byte) []byte {
	sum := sha256.Sum256(body)
	msg := make([]byte, 0, len(nonce)+len(method)+len(path)+sha256.Size)
	msg = append(msg, nonce...)
	msg = append(msg, method...)
	msg = append(msg, path...)
	msg = append(msg, sum[:]...)
	return msg
}

// verifyAuth checks the three X-Lore-* headers against the request. Returns
// the verified device pubkey (hex). Does NOT check enrollment — the caller
// decides (POST /v1/devices self-enrolls).
func (s *Server) verifyAuth(r *http.Request, body []byte) (string, error) {
	devicePub := r.Header.Get("X-Lore-Device")
	nonce := r.Header.Get("X-Lore-Nonce")
	sigHex := r.Header.Get("X-Lore-Sig")
	if devicePub == "" || nonce == "" || sigHex == "" {
		return "", fmt.Errorf("missing X-Lore-Device/X-Lore-Nonce/X-Lore-Sig")
	}
	pub, err := ParsePub(devicePub)
	if err != nil {
		return "", fmt.Errorf("bad device key")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("bad signature encoding")
	}
	if !s.nonces.redeem(nonce, devicePub) {
		return "", fmt.Errorf("unknown, expired, or reused nonce")
	}
	if !ed25519.Verify(pub, authMessage(nonce, r.Method, r.URL.Path, body), sig) {
		return "", fmt.Errorf("signature verification failed")
	}
	return devicePub, nil
}

// verifyEnrollSig checks account_sig = Ed25519(account_priv, "lore-enroll"||device_pub_hex).
func verifyEnrollSig(accountPub, devicePub, sigHex string) error {
	pub, err := ParsePub(accountPub)
	if err != nil {
		return fmt.Errorf("bad account key")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("bad account_sig encoding")
	}
	if !ed25519.Verify(pub, []byte(enrollPrefix+devicePub), sig) {
		return fmt.Errorf("account_sig verification failed")
	}
	return nil
}

// --- unauthenticated-route rate limiting (keybox-by-handle) ---

// rateLimiter is a fixed 1-minute sliding window per key (client IP).
type rateLimiter struct {
	mu    sync.Mutex
	limit int
	hits  map[string][]time.Time
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{limit: perMinute, hits: make(map[string][]time.Time)}
}

// allow records a hit for key and reports whether it is within the limit.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.limit {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// clientIP extracts the remote IP (the relay sits behind cloudflared/a
// reverse proxy in production; we intentionally do not trust X-Forwarded-For
// unless the proxy strips it — using the direct peer is the conservative
// default and correct for local/dev).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
