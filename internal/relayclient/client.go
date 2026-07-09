// Package relayclient is the typed HTTP client for the lore relay
// (internal/relay): challenge-signature auth, device enrollment, space
// registration/grants, encrypted delta log append/read (long-poll),
// snapshots, the account keybox, and handles. It also implements the
// client-side delta crypto (XChaCha20-Poly1305 under the space_key) and the
// signup/login flows shared by the CLI and tests.
//
// Wire contract (pinned by docs/IMPLEMENTATION.md §Relay and internal/relay):
// every authenticated request first mints a nonce via POST /v1/challenge,
// then sends X-Lore-Device / X-Lore-Nonce / X-Lore-Sig where the signature
// is Ed25519 over nonce || method || path || SHA256(body) — path WITHOUT the
// query string.
package relayclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// MaxWait is the server's long-poll cap (relay maxWaitSeconds).
const MaxWait = 60 * time.Second

// APIError is a non-2xx relay response.
type APIError struct {
	StatusCode int
	Msg        string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("relay: HTTP %d: %s", e.StatusCode, e.Msg)
}

// IsNotFound reports whether err is a relay 404.
func IsNotFound(err error) bool { return isStatus(err, http.StatusNotFound) }

// IsConflict reports whether err is a relay 409.
func IsConflict(err error) bool { return isStatus(err, http.StatusConflict) }

// IsForbidden reports whether err is a relay 403.
func IsForbidden(err error) bool { return isStatus(err, http.StatusForbidden) }

func isStatus(err error, code int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == code
}

// Client is an authenticated relay client bound to one device key.
type Client struct {
	base       string
	http       *http.Client
	devicePub  string
	devicePriv ed25519.PrivateKey
	certHdr    string // EncodeDeviceCert(device.Cert), sent on enrollment
}

// New builds a client for the relay at baseURL, signing as device.
func New(baseURL string, device *keys.Device) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("relayclient: relay URL is empty (set relay_url in config.json or pass --relay)")
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return nil, err
	}
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		// Timeout must exceed MaxWait so long-polls are never cut client-side.
		http:       &http.Client{Timeout: MaxWait + 30*time.Second},
		devicePub:  device.DevicePub,
		devicePriv: priv,
		certHdr:    syncproto.EncodeDeviceCert(device.Cert),
	}, nil
}

// DevicePub returns the hex device pubkey this client signs with.
func (c *Client) DevicePub() string { return c.devicePub }

// BaseURL returns the relay base URL.
func (c *Client) BaseURL() string { return c.base }

// challenge mints a single-use auth nonce for this device.
func (c *Client) challenge(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]string{"device_pub": c.devicePub})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/challenge", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", readAPIError(resp)
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("relayclient: challenge response: %w", err)
	}
	return out.Nonce, nil
}

// do runs one challenge-signed request. pathAndQuery may carry a query
// string; the signature covers the bare path only (protocol contract —
// replay across queries is prevented by the single-use nonce).
func (c *Client) do(ctx context.Context, method, pathAndQuery string, body []byte) (*http.Response, error) {
	nonce, err := c.challenge(ctx)
	if err != nil {
		return nil, err
	}
	path := pathAndQuery
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	sum := sha256.Sum256(body)
	msg := make([]byte, 0, len(nonce)+len(method)+len(path)+sha256.Size)
	msg = append(msg, nonce...)
	msg = append(msg, method...)
	msg = append(msg, path...)
	msg = append(msg, sum[:]...)
	sig := ed25519.Sign(c.devicePriv, msg)

	req, err := http.NewRequestWithContext(ctx, method, c.base+pathAndQuery, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Lore-Device", c.devicePub)
	req.Header.Set("X-Lore-Nonce", nonce)
	req.Header.Set("X-Lore-Sig", hex.EncodeToString(sig))
	return c.http.Do(req)
}

// doJSON runs do and decodes a 2xx JSON response into out (out may be nil).
func (c *Client) doJSON(ctx context.Context, method, pathAndQuery string, body []byte, out any) error {
	resp, err := c.do(ctx, method, pathAndQuery, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return readAPIError(resp)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// readAPIError extracts {"error": msg} (or raw body) into an *APIError.
func readAPIError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	return &APIError{StatusCode: resp.StatusCode, Msg: msg}
}

// EnrollDevice self-enrolls this client's device under account:
// POST /v1/devices with account_sig = Ed25519(account_priv,
// "lore-enroll"||device_pub_hex). Idempotent for the same pairing.
func (c *Client) EnrollDevice(ctx context.Context, account *keys.Account) error {
	signKey, err := account.SigningKey()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(signKey, []byte("lore-enroll"+c.devicePub))
	body, _ := json.Marshal(map[string]string{
		"account_pub": account.SignPub,
		"device_pub":  c.devicePub,
		"cert":        c.certHdr,
		"account_sig": hex.EncodeToString(sig),
	})
	return c.doJSON(ctx, http.MethodPost, "/v1/devices", body, nil)
}

// RegisterSpace registers a blinded space id, owner = caller's account.
// Idempotent for the owner; IsConflict(err) when another account owns it
// (normal for shared spaces registered by the inviter).
func (c *Client) RegisterSpace(ctx context.Context, blindedID string) error {
	body, _ := json.Marshal(map[string]string{"blinded_id": blindedID})
	return c.doJSON(ctx, http.MethodPost, "/v1/spaces", body, nil)
}

// Grant gives accountPub access to a space this account owns.
func (c *Client) Grant(ctx context.Context, blindedID, accountPub string) error {
	body, _ := json.Marshal(map[string]string{"account_pub": accountPub})
	return c.doJSON(ctx, http.MethodPost, "/v1/spaces/"+blindedID+"/grant", body, nil)
}

// Revoke removes accountPub's access to an owned space.
func (c *Client) Revoke(ctx context.Context, blindedID, accountPub string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1/spaces/"+blindedID+"/grant/"+accountPub, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return readAPIError(resp)
	}
	return nil
}

// AppendLog appends an opaque encrypted delta; returns its assigned seq.
func (c *Client) AppendLog(ctx context.Context, blindedID string, data []byte) (int64, error) {
	var out struct {
		Seq int64 `json:"seq"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/spaces/"+blindedID+"/log", data, &out); err != nil {
		return 0, err
	}
	return out.Seq, nil
}

// LogEntry is one decoded element of a log read.
type LogEntry struct {
	Seq  int64
	Data []byte
}

// ReadLog reads deltas with seq >= from. wait > 0 long-polls up to that
// duration (server caps at MaxWait). Returns (nil, nil) when the poll
// expires empty (server 204). Clients pass from = lastSeen+1.
func (c *Client) ReadLog(ctx context.Context, blindedID string, from int64, wait time.Duration) ([]LogEntry, error) {
	q := "/v1/spaces/" + blindedID + "/log?from=" + strconv.FormatInt(from, 10)
	if wait > 0 {
		q += "&wait=" + strconv.Itoa(int(wait.Round(time.Second)/time.Second))
	}
	resp, err := c.do(ctx, http.MethodGet, q, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}
	var items []struct {
		Seq  int64  `json:"seq"`
		Data string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("relayclient: log response: %w", err)
	}
	out := make([]LogEntry, len(items))
	for i, it := range items {
		b, err := base64.StdEncoding.DecodeString(it.Data)
		if err != nil {
			return nil, fmt.Errorf("relayclient: log seq %d: %w", it.Seq, err)
		}
		out[i] = LogEntry{Seq: it.Seq, Data: b}
	}
	return out, nil
}

// GetSnapshot fetches the current snapshot blob and the seq it covers.
// IsNotFound(err) when the space has no snapshot yet.
func (c *Client) GetSnapshot(ctx context.Context, blindedID string) ([]byte, int64, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/spaces/"+blindedID+"/snapshot", nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, readAPIError(resp)
	}
	upto, err := strconv.ParseInt(resp.Header.Get("X-Lore-Upto"), 10, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("relayclient: snapshot X-Lore-Upto: %w", err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return data, upto, nil
}

// PutSnapshot uploads a compacted snapshot covering seqs <= upto; the relay
// drops the folded log prefix.
func (c *Client) PutSnapshot(ctx context.Context, blindedID string, upto int64, data []byte) error {
	return c.doJSON(ctx, http.MethodPut,
		"/v1/spaces/"+blindedID+"/snapshot?upto="+strconv.FormatInt(upto, 10), data, nil)
}

// PutKeybox stores the wrapped account key (opaque bytes, <= 64 KB).
func (c *Client) PutKeybox(ctx context.Context, keybox []byte) error {
	resp, err := c.do(ctx, http.MethodPut, "/v1/account/keybox", keybox)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return readAPIError(resp)
	}
	return nil
}

// GetKeybox fetches this account's own keybox (device-authenticated).
func (c *Client) GetKeybox(ctx context.Context) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, "/v1/account/keybox", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}
	return io.ReadAll(resp.Body)
}

// ClaimHandle claims (or changes) the account's unique handle.
func (c *Client) ClaimHandle(ctx context.Context, handle string) error {
	body, _ := json.Marshal(map[string]string{"handle": handle})
	return c.doJSON(ctx, http.MethodPost, "/v1/account/handle", body, nil)
}

// --- unauthenticated routes (no device key required) ---

// ResolveHandle maps a handle to its account pubkey (open route).
func ResolveHandle(ctx context.Context, baseURL, handle string) (string, error) {
	resp, err := openGET(ctx, baseURL, "/v1/accounts/"+handle)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", readAPIError(resp)
	}
	var out struct {
		AccountPub string `json:"account_pub"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.AccountPub, nil
}

// FetchKeyboxByHandle fetches the Argon2id-wrapped keybox for a handle.
// UNAUTHENTICATED by design (fresh login has no enrolled device yet);
// rate-limited server-side to 5/min/IP.
func FetchKeyboxByHandle(ctx context.Context, baseURL, handle string) ([]byte, error) {
	resp, err := openGET(ctx, baseURL, "/v1/accounts/"+handle+"/keybox")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}
	return io.ReadAll(resp.Body)
}

func openGET(ctx context.Context, baseURL, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	return (&http.Client{Timeout: 30 * time.Second}).Do(req)
}
