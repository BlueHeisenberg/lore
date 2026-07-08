package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BlueHeisenberg/agentmesh/pkg/discovery"
	"github.com/BlueHeisenberg/agentmesh/pkg/identity"
	"github.com/BlueHeisenberg/agentmesh/pkg/transport"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// LAN device enrollment — trust model
//
// The NEW device (`lore enroll`) shows a short code on its screen and
// listens on a temporary mTLS endpoint. The EXISTING device (`lore approve
// <code>`) is given that code by the human who can see both screens: the
// code spoken/read between humans IS the authentication. The crypto binds
// that human decision to a key:
//
//  1. Enrollee generates an ephemeral X25519 keypair and an 8-char code.
//  2. Approver locates the enrollee (mDNS or --addr), sends a random
//     challenge, and receives (eph_pub, HMAC(code, challenge||eph_pub)).
//     Only a device that knows the code can produce that MAC, so the
//     approver knows eph_pub belongs to the device the human is looking at
//     — a spoofed enrollee on the LAN cannot substitute its own key.
//  3. Approver seals {code, account keys, spaces incl. space_keys} to
//     eph_pub with box.SealAnonymous and POSTs it. The code is the auth,
//     the ephemeral key is the confidential channel.
//  4. Enrollee opens the box, re-checks the code, persists account.json,
//     signs a fresh device keypair with the received account key
//     (keys.GenerateDevice), and seeds its store with the space rows so
//     blinded-id sync intersects immediately.
//
// The enrollee's TLS key is throwaway (channel confidentiality comes from
// the box, not TLS); the real device key is minted only after the account
// arrives. The code has ~40 bits of entropy and a single-use endpoint —
// fine for a human-supervised LAN exchange, not for internet exposure.

// enrollCodeLen is the length of the human-relayed enrollment code.
const enrollCodeLen = 8

// enrollNamePrefix marks enrollee mDNS advertisements (see discovery.go).
const enrollNamePrefix = "enroll|"

func newEnrollCode() (string, error) {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	raw := make([]byte, enrollCodeLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, enrollCodeLen)
	for i, b := range raw {
		out[i] = crockford[int(b)%len(crockford)]
	}
	return string(out), nil
}

// enrollMAC computes HMAC-SHA256(normalized code, challenge || eph_pub).
func enrollMAC(code string, challenge, ephPub []byte) []byte {
	m := hmac.New(sha256.New, []byte(keys.NormalizeRecoveryCode(code)))
	m.Write(challenge)
	m.Write(ephPub)
	return m.Sum(nil)
}

// Enrollee is a running `lore enroll` listener on a new device.
type Enrollee struct {
	Code   string
	EphPub string // hex X25519 pubkey, shown alongside the code
	Port   int

	home    string
	name    string
	ephPriv [32]byte
	ephPub  [32]byte
	server  *transport.Server
	stopAdv func()
	done    chan error
}

// StartEnrollee begins enrollment on a NEW device: generates the code and
// ephemeral key, starts the temporary endpoint, and (unless mdns is false)
// advertises it. home must not already hold an account.
func StartEnrollee(home, name string, lan, mdns bool) (*Enrollee, error) {
	if _, err := os.Stat(filepath.Join(home, keys.AccountFile)); err == nil {
		return nil, fmt.Errorf("already initialized at %s", home)
	}
	code, err := newEnrollCode()
	if err != nil {
		return nil, err
	}
	e := &Enrollee{
		Code: code,
		home: home,
		name: name,
		done: make(chan error, 1),
	}
	if _, err := rand.Read(e.ephPriv[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(e.ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(e.ephPub[:], pub)
	e.EphPub = hex.EncodeToString(pub)

	// Throwaway TLS identity for the enrollment channel only.
	_, tlsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tlsID := identity.FromPrivateKey(tlsPriv)
	cert, err := tlsID.TLSCertificate()
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /lore/v1/enroll", e.handleInfo)
	mux.HandleFunc("POST /lore/v1/enroll", e.handleEnroll)
	e.server = &transport.Server{Cert: cert, Handler: mux}
	port, err := e.server.Start(lan)
	if err != nil {
		return nil, err
	}
	e.Port = port

	if mdns {
		ifaces, ips := ifacesAndIPs(lan)
		stop, err := discovery.Advertise(ServiceType, enrollNamePrefix+name,
			tlsID.PeerID(), port, ifaces, ips)
		if err != nil {
			e.Close()
			return nil, err
		}
		e.stopAdv = stop
	}
	return e, nil
}

// handleInfo answers the approver's challenge, proving code knowledge.
func (e *Enrollee) handleInfo(w http.ResponseWriter, r *http.Request) {
	challenge, err := hex.DecodeString(r.URL.Query().Get("challenge"))
	if err != nil || len(challenge) < 8 {
		http.Error(w, "bad challenge", http.StatusBadRequest)
		return
	}
	transport.WriteJSON(w, http.StatusOK, syncproto.EnrollInfo{
		EphPub: e.EphPub,
		MAC:    hex.EncodeToString(enrollMAC(e.Code, challenge, e.ephPub[:])),
	})
}

// handleEnroll receives the sealed account payload and completes enrollment.
func (e *Enrollee) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req syncproto.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sealed, err := base64.StdEncoding.DecodeString(req.Box)
	if err != nil {
		http.Error(w, "bad box encoding", http.StatusBadRequest)
		return
	}
	plain, ok := box.OpenAnonymous(nil, sealed, &e.ephPub, &e.ephPriv)
	if !ok {
		http.Error(w, "box does not open", http.StatusBadRequest)
		return
	}
	var payload syncproto.EnrollPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	if !hmac.Equal(
		[]byte(keys.NormalizeRecoveryCode(payload.Code)),
		[]byte(keys.NormalizeRecoveryCode(e.Code))) {
		http.Error(w, "enroll code mismatch", http.StatusForbidden)
		return
	}
	device, err := completeEnrollment(e.home, e.name, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		e.finish(err)
		return
	}
	transport.WriteJSON(w, http.StatusOK, syncproto.EnrollResponse{
		DeviceID: device.DeviceID(),
		Name:     device.Name,
	})
	e.finish(nil)
}

func (e *Enrollee) finish(err error) {
	select {
	case e.done <- err:
	default:
	}
}

// completeEnrollment persists the received account, mints and certifies this
// device's keypair, and seeds the store with the space rows (ids and keys
// preserved so blinded-id intersection works from the first sync round).
func completeEnrollment(home, name string, p syncproto.EnrollPayload) (*keys.Device, error) {
	if err := p.Account.VerifyEncPub(); err != nil {
		return nil, fmt.Errorf("received account invalid: %w", err)
	}
	if err := keys.SaveAccount(home, &p.Account); err != nil {
		return nil, err
	}
	device, err := keys.GenerateDevice(name, &p.Account)
	if err != nil {
		return nil, err
	}
	if err := keys.SaveDevice(home, device); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(home, "blobs"), 0o700); err != nil {
		return nil, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID:  p.Account.AccountID(),
		DeviceID:   device.DeviceID(),
		DevicePriv: priv,
	})
	if err != nil {
		return nil, err
	}
	defer st.Close()
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	for _, sp := range p.Spaces {
		if err := syncproto.InsertSpaceRecord(db, sp); err != nil {
			return nil, err
		}
	}
	return device, nil
}

// Wait blocks until enrollment completes (nil), fails, or ctx expires.
func (e *Enrollee) Wait(ctx context.Context) error {
	select {
	case err := <-e.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the temporary endpoint and advertisement.
func (e *Enrollee) Close() {
	if e.stopAdv != nil {
		e.stopAdv()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e.server.Stop(ctx)
}

// Approve runs on an EXISTING device: locate the enrollee (explicit addr or
// mDNS), verify it knows code, then send it the account and space keys.
// Returns the new device's id.
func Approve(ctx context.Context, home, code, addr string) (string, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return "", err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return "", err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return "", err
	}
	cert, err := identity.FromPrivateKey(priv).TLSCertificate()
	if err != nil {
		return "", err
	}
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return "", err
	}
	spaces, err := syncproto.ListSpaceRecords(db)
	db.Close()
	if err != nil {
		return "", err
	}

	candidates := []string{addr}
	if addr == "" {
		candidates, err = findEnrollees(ctx, device.DeviceID())
		if err != nil {
			return "", err
		}
		if len(candidates) == 0 {
			return "", errors.New("no enrolling device found via mDNS (pass --addr host:port)")
		}
	}

	httpc := enrollClient(cert)
	var lastErr error = errors.New("no enrollee matched the code")
	for _, cand := range candidates {
		id, err := approveOne(ctx, httpc, cand, code, account, spaces)
		if err == nil {
			return id, nil
		}
		lastErr = fmt.Errorf("%s: %w", cand, err)
	}
	return "", lastErr
}

// enrollClient builds a client for the enrollee's throwaway TLS identity:
// no pinning (the key is ephemeral and unknown), self-signed check only.
// Confidentiality does not depend on this TLS session — the payload is
// sealed to the code-authenticated ephemeral X25519 key.
func enrollClient(cert tls.Certificate) *http.Client {
	cfg := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: transport.VerifySelfSignedCert,
		MinVersion:            tls.VersionTLS13,
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// findEnrollees browses mDNS briefly and returns candidate addresses of
// advertised enrollees.
func findEnrollees(ctx context.Context, selfID string) ([]string, error) {
	reg := discovery.NewRegistry(selfID)
	bctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	ifaces, _ := ifacesAndIPs(true)
	_ = discovery.Browse(bctx, ServiceType, reg, ifaces) // returns at ctx end
	var out []string
	for _, p := range reg.List() {
		if strings.HasPrefix(p.Name, enrollNamePrefix) {
			out = append(out, p.Addr)
		}
	}
	return out, nil
}

// approveOne runs the challenge + seal + POST against one candidate.
func approveOne(ctx context.Context, httpc *http.Client, addr, code string,
	account *keys.Account, spaces []syncproto.SpaceRecord) (string, error) {

	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return "", err
	}
	base := "https://" + addr
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/lore/v1/enroll?challenge="+hex.EncodeToString(challenge), nil)
	if err != nil {
		return "", err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", err
	}
	var info syncproto.EnrollInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	ephPub, err := hex.DecodeString(info.EphPub)
	if err != nil || len(ephPub) != 32 {
		return "", errors.New("bad ephemeral pubkey")
	}
	mac, err := hex.DecodeString(info.MAC)
	if err != nil {
		return "", errors.New("bad mac encoding")
	}
	if !hmac.Equal(mac, enrollMAC(code, challenge, ephPub)) {
		return "", errors.New("code proof failed (wrong code or wrong device)")
	}

	payload, err := json.Marshal(syncproto.EnrollPayload{
		Code:    code,
		Account: *account,
		Spaces:  spaces,
	})
	if err != nil {
		return "", err
	}
	var pub [32]byte
	copy(pub[:], ephPub)
	sealed, err := box.SealAnonymous(nil, payload, &pub, rand.Reader)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(syncproto.EnrollRequest{Box: base64.StdEncoding.EncodeToString(sealed)})
	post, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/lore/v1/enroll", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	post.Header.Set("Content-Type", "application/json")
	presp, err := httpc.Do(post)
	if err != nil {
		return "", err
	}
	defer presp.Body.Close()
	if presp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(presp.Body, 4096))
		return "", fmt.Errorf("enroll rejected: %s: %s", presp.Status, strings.TrimSpace(string(msg)))
	}
	var ack syncproto.EnrollResponse
	if err := json.NewDecoder(presp.Body).Decode(&ack); err != nil {
		return "", err
	}
	return ack.DeviceID, nil
}
