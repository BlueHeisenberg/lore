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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BlueHeisenberg/agentmesh/pkg/discovery"
	"github.com/BlueHeisenberg/agentmesh/pkg/identity"
	"github.com/BlueHeisenberg/agentmesh/pkg/transport"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"golang.org/x/crypto/nacl/box"
)

// LAN space invite — trust model
//
// Mirrors device enrollment (enroll.go) with the roles reversed and the
// exchange crossing ACCOUNTS instead of staying inside one:
//
//	INVITER (owner)   runs `lore space invite <space>` — shows the code,
//	                  listens on a temporary mTLS endpoint.
//	INVITEE           runs `lore join <code>` — finds the inviter (mDNS or
//	                  --addr) and connects.
//
// The code read between humans is the authentication; the crypto binds it:
//
//  1. Invitee sends a random challenge; inviter answers with its account
//     keys, a session nonce, and HMAC(code, challenge||keys||nonce). Only
//     the device showing the code can produce that MAC, so the invitee
//     knows those account keys belong to the person it is talking to.
//  2. BOTH humans compare a 4-word fingerprint derived from the two account
//     pubkeys (space.FingerprintWords) and confirm y/N — key substitution
//     by a MITM changes the words on one side.
//  3. Invitee introduces its own account keys with HMAC(code, "join"||
//     nonce||keys) — a LAN spoofer without the code cannot inject keys.
//  4. Inviter (after its human confirms) appends a new signed member-doc
//     version naming the invitee, wraps the space_key to the invitee's
//     encryption key inside that doc, and answers with {space row (key
//     stripped), member-doc chain} sealed to the invitee's enc key.
//  5. Invitee verifies the doc chain, finds itself in the latest version,
//     unwraps the space_key, and stores space + docs. Entries then flow
//     over normal sync.

// inviteSessionState tracks the single outstanding join attempt.
type inviteSessionState struct {
	mu    sync.Mutex
	nonce []byte // outstanding session nonce (single active join attempt)
}

// inviteNamePrefix marks inviter mDNS advertisements.
const inviteNamePrefix = "invite|"

// inviteMAC computes HMAC-SHA256 keyed with the normalized invite code over
// the given parts, in order.
func inviteMAC(code string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, []byte(keys.NormalizeRecoveryCode(code)))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// InviteConfirm is the human gate: shown the fingerprint words and the other
// party's account id (and display name when known), it returns whether to
// proceed. CLIs prompt y/N; tests pass a constant.
type InviteConfirm func(fingerprint, otherAccount, otherName string) bool

// Joined describes a completed invite from the inviter's perspective.
type Joined struct {
	Account string // invitee account id
	Name    string // invitee display name
	Role    string
	DocV    int64 // member-doc version that added them
}

// Inviter is a running `lore space invite` listener on the owner's device.
type Inviter struct {
	Code string
	Port int

	home    string
	role    string
	sp      store.Space
	account *keys.Account
	device  *keys.Device
	st      *store.Store
	confirm InviteConfirm

	session inviteSessionState
	server  *transport.Server
	stopAdv func()
	done    chan inviteOutcome
}

type inviteOutcome struct {
	joined Joined
	err    error
}

// StartInviter begins an invite for a shared space: generates the code and
// starts the temporary endpoint (advertised over mDNS unless mdns is false).
// The caller must be an owner per the space's latest verified member doc.
// confirm gates every join request; role is the role granted (writer|reader).
func StartInviter(home string, sp store.Space, role string, lan, mdns bool, confirm InviteConfirm) (*Inviter, error) {
	if sp.Kind != "shared" {
		return nil, store.ErrPersonalSpace
	}
	if role != space.RoleWriter && role != space.RoleReader {
		return nil, fmt.Errorf("invite role must be writer or reader, got %q", role)
	}
	if confirm == nil {
		return nil, errors.New("nil confirm callback")
	}
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return nil, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID: account.AccountID(), DeviceID: device.DeviceID(), DevicePriv: priv,
	})
	if err != nil {
		return nil, err
	}
	// Fail fast: we must be an owner to sign the next member-doc version.
	latest, ok, err := st.LatestMemberDoc(sp.SpaceID)
	if err == nil && !ok {
		err = fmt.Errorf("space %s has no verified member list (create it with `lore space create` / `lore project init`)", sp.Name)
	}
	if err == nil && latest.Role(account.AccountID()) != space.RoleOwner {
		err = fmt.Errorf("only an owner can invite; this account is %q in space %s",
			latest.Role(account.AccountID()), sp.Name)
	}
	if err != nil {
		st.Close()
		return nil, err
	}

	code, err := newEnrollCode()
	if err != nil {
		st.Close()
		return nil, err
	}
	inv := &Inviter{
		Code:    code,
		home:    home,
		role:    role,
		sp:      sp,
		account: account,
		device:  device,
		st:      st,
		confirm: confirm,
		done:    make(chan inviteOutcome, 1),
	}

	cert, err := identity.FromPrivateKey(priv).TLSCertificate()
	if err != nil {
		st.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /lore/v1/invite", inv.handleInfo)
	mux.HandleFunc("POST /lore/v1/invite", inv.handleJoin)
	inv.server = &transport.Server{Cert: cert, Handler: mux}
	port, err := inv.server.Start(lan)
	if err != nil {
		st.Close()
		return nil, err
	}
	inv.Port = port

	if mdns {
		ifaces, ips := ifacesAndIPs(lan)
		stop, err := discovery.Advertise(ServiceType, inviteNamePrefix+device.Name,
			device.DeviceID(), port, ifaces, ips)
		if err != nil {
			inv.Close()
			return nil, err
		}
		inv.stopAdv = stop
	}
	return inv, nil
}

// handleInfo proves code knowledge and hands out the inviter's account keys
// plus the session nonce.
func (inv *Inviter) handleInfo(w http.ResponseWriter, r *http.Request) {
	challenge, err := hex.DecodeString(r.URL.Query().Get("challenge"))
	if err != nil || len(challenge) < 8 {
		http.Error(w, "bad challenge", http.StatusBadRequest)
		return
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "entropy failure", http.StatusInternalServerError)
		return
	}
	inv.session.mu.Lock()
	inv.session.nonce = nonce
	inv.session.mu.Unlock()

	acct, enc := inv.account.SignPub, inv.account.EncPub
	transport.WriteJSON(w, http.StatusOK, syncproto.InviteInfo{
		AccountPub: acct,
		EncPub:     enc,
		EncPubSig:  inv.account.EncPubSig,
		Nonce:      hex.EncodeToString(nonce),
		MAC:        hex.EncodeToString(inviteMAC(inv.Code, challenge, []byte(acct), []byte(enc), nonce)),
	})
}

// handleJoin verifies the invitee's code proof and key binding, asks the
// human, appends the member-doc version, and returns the sealed payload.
func (inv *Inviter) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req syncproto.JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	nonce, err := hex.DecodeString(req.Nonce)
	if err != nil {
		http.Error(w, "bad nonce", http.StatusBadRequest)
		return
	}
	inv.session.mu.Lock()
	current := inv.session.nonce
	inv.session.nonce = nil // single use
	inv.session.mu.Unlock()
	if current == nil || !hmac.Equal(nonce, current) {
		http.Error(w, "stale or unknown session (re-run lore join)", http.StatusForbidden)
		return
	}
	mac, err := hex.DecodeString(req.MAC)
	if err != nil || !hmac.Equal(mac, inviteMAC(inv.Code, []byte("join"), nonce,
		[]byte(req.AccountPub), []byte(req.EncPub))) {
		http.Error(w, "code proof failed (wrong code or wrong device)", http.StatusForbidden)
		return
	}
	if err := verifyEncBinding(req.AccountPub, req.EncPub, req.EncPubSig); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if req.AccountPub == inv.account.AccountID() {
		http.Error(w, "that is this same account — use `lore enroll` for new devices", http.StatusConflict)
		return
	}

	// Human gate: same words must show on both screens.
	words := space.FingerprintWords(inv.account.AccountID(), req.AccountPub)
	if !inv.confirm(words, req.AccountPub, req.Name) {
		http.Error(w, "invite declined by inviter", http.StatusForbidden)
		return
	}

	sealed, docV, err := inv.admit(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		inv.finish(inviteOutcome{err: err})
		return
	}
	transport.WriteJSON(w, http.StatusOK, syncproto.JoinResponse{Box: sealed})
	inv.finish(inviteOutcome{joined: Joined{
		Account: req.AccountPub, Name: req.Name, Role: inv.role, DocV: docV,
	}})
}

// admit appends the member-doc version naming the invitee and seals the
// invite payload to the invitee's encryption key.
func (inv *Inviter) admit(req syncproto.JoinRequest) (string, int64, error) {
	latest, ok, err := inv.st.LatestMemberDoc(inv.sp.SpaceID)
	if err != nil {
		return "", 0, err
	}
	if !ok {
		return "", 0, fmt.Errorf("space %s lost its verified member list", inv.sp.Name)
	}
	if _, already := latest.Member(req.AccountPub); already {
		return "", 0, fmt.Errorf("account %s is already a member of %s", shortID(req.AccountPub), inv.sp.Name)
	}
	wrapped, err := space.WrapSpaceKey(inv.sp.SpaceKey, req.EncPub)
	if err != nil {
		return "", 0, err
	}
	signPriv, err := inv.account.SigningKey()
	if err != nil {
		return "", 0, err
	}
	members := append(append([]space.Member(nil), latest.Members...), space.Member{
		AccountPub: req.AccountPub, EncPub: req.EncPub, Role: inv.role, WrappedSpaceKey: wrapped,
	})
	next, err := space.Evolve(latest, members, inv.account.AccountID(), signPriv)
	if err != nil {
		return "", 0, err
	}
	if err := inv.st.AddMemberDoc(inv.sp.SpaceID, next); err != nil {
		return "", 0, err
	}

	db, err := syncproto.OpenDB(filepath.Join(inv.home, "lore.db"))
	if err != nil {
		return "", 0, err
	}
	docs, err := syncproto.MemberDocs(db, inv.sp.SpaceID)
	db.Close()
	if err != nil {
		return "", 0, err
	}
	rec := syncproto.SpaceRecord{
		SpaceID: inv.sp.SpaceID, Kind: inv.sp.Kind, Name: inv.sp.Name,
		ProjectRef: inv.sp.ProjectRef, SpaceKey: nil, // key travels only wrapped, inside the doc
		CreatedAt: inv.sp.CreatedAt,
	}
	payload, err := json.Marshal(syncproto.InvitePayload{Space: rec, MemberDocs: docs, Role: inv.role})
	if err != nil {
		return "", 0, err
	}
	encPub, err := decodeKey32(req.EncPub)
	if err != nil {
		return "", 0, err
	}
	sealed, err := box.SealAnonymous(nil, payload, &encPub, rand.Reader)
	if err != nil {
		return "", 0, err
	}
	return base64.StdEncoding.EncodeToString(sealed), next.Version, nil
}

func (inv *Inviter) finish(o inviteOutcome) {
	select {
	case inv.done <- o:
	default:
	}
}

// Wait blocks until a join completes, fails, or ctx expires.
func (inv *Inviter) Wait(ctx context.Context) (Joined, error) {
	select {
	case o := <-inv.done:
		return o.joined, o.err
	case <-ctx.Done():
		return Joined{}, ctx.Err()
	}
}

// Close tears down the endpoint, advertisement and store handle.
func (inv *Inviter) Close() {
	if inv.stopAdv != nil {
		inv.stopAdv()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	inv.server.Stop(ctx)
	_ = inv.st.Close()
}

// JoinResult describes a completed invite from the invitee's perspective.
type JoinResult struct {
	Space          store.Space
	Role           string
	InviterAccount string
	Members        int
}

// ErrJoinDeclined is returned when the local human rejects the fingerprint.
var ErrJoinDeclined = errors.New("join declined (fingerprint not confirmed)")

// Join runs on the INVITEE device: locate the inviter (explicit addr or
// mDNS), verify it knows the code, confirm the fingerprint (confirm
// callback), introduce our account keys, and store the received space +
// member docs. home must already be initialized (`lore init`).
func Join(ctx context.Context, home, code, addr string, confirm InviteConfirm) (JoinResult, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return JoinResult{}, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return JoinResult{}, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return JoinResult{}, err
	}
	cert, err := identity.FromPrivateKey(priv).TLSCertificate()
	if err != nil {
		return JoinResult{}, err
	}
	if confirm == nil {
		return JoinResult{}, errors.New("nil confirm callback")
	}

	candidates := []string{addr}
	if addr == "" {
		candidates, err = findInviters(ctx, device.DeviceID())
		if err != nil {
			return JoinResult{}, err
		}
		if len(candidates) == 0 {
			return JoinResult{}, errors.New("no inviting device found via mDNS (pass --addr host:port)")
		}
	}

	httpc := joinClient(cert)
	var lastErr error = errors.New("no inviter matched the code")
	for _, cand := range candidates {
		res, err := joinOne(ctx, httpc, cand, code, account, device.Name, confirm)
		if err == nil {
			return persistJoin(home, res)
		}
		if errors.Is(err, ErrJoinDeclined) {
			return JoinResult{}, err // human said no: stop, do not probe others
		}
		lastErr = fmt.Errorf("%s: %w", cand, err)
	}
	return JoinResult{}, lastErr
}

// joinClient: no server pinning (we do not know the inviter's device key
// yet) — self-signed identity check only. Authentication comes from the
// code MAC + fingerprint confirm; confidentiality from the sealed payload.
// Generous timeout: the response waits on the inviter's human confirming.
func joinClient(cert tls.Certificate) *http.Client {
	cfg := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: transport.VerifySelfSignedCert,
		MinVersion:            tls.VersionTLS13,
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// findInviters browses mDNS briefly for advertised inviters.
func findInviters(ctx context.Context, selfID string) ([]string, error) {
	reg := discovery.NewRegistry(selfID)
	bctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	ifaces, _ := ifacesAndIPs(true)
	_ = discovery.Browse(bctx, ServiceType, reg, ifaces)
	var out []string
	for _, p := range reg.List() {
		if strings.HasPrefix(p.Name, inviteNamePrefix) {
			out = append(out, p.Addr)
		}
	}
	return out, nil
}

// pendingJoin is what joinOne hands to persistJoin after verification.
type pendingJoin struct {
	payload        syncproto.InvitePayload
	latest         space.MemberDoc
	verified       []space.MemberDoc
	spaceKey       []byte
	selfAccount    string
	inviterAccount string
}

// joinOne runs challenge -> fingerprint confirm -> introduction -> payload
// verification against one candidate address.
func joinOne(ctx context.Context, httpc *http.Client, addr, code string,
	account *keys.Account, deviceName string, confirm InviteConfirm) (pendingJoin, error) {

	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return pendingJoin{}, err
	}
	base := "https://" + addr
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/lore/v1/invite?challenge="+hex.EncodeToString(challenge), nil)
	if err != nil {
		return pendingJoin{}, err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return pendingJoin{}, err
	}
	var info syncproto.InviteInfo
	err = json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if err != nil {
		return pendingJoin{}, err
	}
	nonce, err := hex.DecodeString(info.Nonce)
	if err != nil || len(nonce) < 8 {
		return pendingJoin{}, errors.New("bad session nonce")
	}
	mac, err := hex.DecodeString(info.MAC)
	if err != nil || !hmac.Equal(mac, inviteMAC(code, challenge,
		[]byte(info.AccountPub), []byte(info.EncPub), nonce)) {
		return pendingJoin{}, errors.New("code proof failed (wrong code or wrong device)")
	}
	if err := verifyEncBinding(info.AccountPub, info.EncPub, info.EncPubSig); err != nil {
		return pendingJoin{}, err
	}
	if info.AccountPub == account.AccountID() {
		return pendingJoin{}, errors.New("inviter is this same account — use `lore enroll` for new devices")
	}

	// Human gate BEFORE we introduce ourselves.
	words := space.FingerprintWords(info.AccountPub, account.AccountID())
	if !confirm(words, info.AccountPub, "") {
		return pendingJoin{}, ErrJoinDeclined
	}

	jr := syncproto.JoinRequest{
		AccountPub: account.SignPub,
		EncPub:     account.EncPub,
		EncPubSig:  account.EncPubSig,
		Name:       deviceName,
		Nonce:      info.Nonce,
		MAC: hex.EncodeToString(inviteMAC(code, []byte("join"), nonce,
			[]byte(account.SignPub), []byte(account.EncPub))),
	}
	body, _ := json.Marshal(jr)
	post, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/lore/v1/invite", strings.NewReader(string(body)))
	if err != nil {
		return pendingJoin{}, err
	}
	post.Header.Set("Content-Type", "application/json")
	presp, err := httpc.Do(post)
	if err != nil {
		return pendingJoin{}, err
	}
	defer presp.Body.Close()
	if presp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(presp.Body, 4096))
		return pendingJoin{}, fmt.Errorf("join rejected: %s: %s", presp.Status, strings.TrimSpace(string(msg)))
	}
	var ack syncproto.JoinResponse
	if err := json.NewDecoder(presp.Body).Decode(&ack); err != nil {
		return pendingJoin{}, err
	}

	sealed, err := base64.StdEncoding.DecodeString(ack.Box)
	if err != nil {
		return pendingJoin{}, errors.New("bad box encoding")
	}
	encPub, err := decodeKey32(account.EncPub)
	if err != nil {
		return pendingJoin{}, err
	}
	encPriv, err := decodeKey32(account.EncPriv)
	if err != nil {
		return pendingJoin{}, err
	}
	plain, ok := box.OpenAnonymous(nil, sealed, &encPub, &encPriv)
	if !ok {
		return pendingJoin{}, errors.New("invite payload does not open with this account's encryption key")
	}
	var payload syncproto.InvitePayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return pendingJoin{}, fmt.Errorf("bad invite payload: %w", err)
	}
	return verifyInvitePayload(payload, account, info.AccountPub)
}

// verifyInvitePayload enforces everything the invitee must not take on
// faith: shared kind only, verified member-doc chain, self present in the
// latest version, unwrappable space key.
func verifyInvitePayload(payload syncproto.InvitePayload, account *keys.Account, inviterAccount string) (pendingJoin, error) {
	if payload.Space.Kind != "shared" {
		return pendingJoin{}, fmt.Errorf("refusing invite to a %q space", payload.Space.Kind)
	}
	raws := make([]space.RawDoc, len(payload.MemberDocs))
	for i, d := range payload.MemberDocs {
		raws[i] = space.RawDoc{Version: d.Version, Doc: d.Doc, Sig: d.Sig}
	}
	verified := space.VerifiedDocs(payload.Space.SpaceID, raws)
	if len(verified) == 0 {
		return pendingJoin{}, errors.New("invite carries no verifiable member list")
	}
	latest := verified[len(verified)-1]
	me, ok := latest.Member(account.AccountID())
	if !ok {
		return pendingJoin{}, errors.New("latest member list does not include this account")
	}
	spaceKey, err := space.UnwrapSpaceKey(me.WrappedSpaceKey, account.EncPub, account.EncPriv)
	if err != nil {
		return pendingJoin{}, err
	}
	if len(spaceKey) != 32 {
		return pendingJoin{}, fmt.Errorf("space key has bad length %d", len(spaceKey))
	}
	return pendingJoin{
		payload:        payload,
		latest:         latest,
		verified:       verified,
		spaceKey:       spaceKey,
		selfAccount:    account.AccountID(),
		inviterAccount: inviterAccount,
	}, nil
}

// persistJoin stores the space row (with the unwrapped key) and the verified
// member docs.
func persistJoin(home string, p pendingJoin) (JoinResult, error) {
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return JoinResult{}, err
	}
	defer db.Close()
	rec := p.payload.Space
	rec.SpaceKey = p.spaceKey
	if err := syncproto.InsertSpaceRecord(db, rec); err != nil {
		return JoinResult{}, err
	}
	byVersion := map[int64]syncproto.MemberDoc{}
	for _, d := range p.payload.MemberDocs {
		byVersion[d.Version] = d
	}
	for _, v := range p.verified {
		if d, ok := byVersion[v.Version]; ok {
			if err := syncproto.InsertMemberDoc(db, rec.SpaceID, d); err != nil {
				return JoinResult{}, err
			}
		}
	}
	return JoinResult{
		Space: store.Space{
			SpaceID: rec.SpaceID, Kind: rec.Kind, Name: rec.Name,
			ProjectRef: rec.ProjectRef, SpaceKey: p.spaceKey, CreatedAt: rec.CreatedAt,
		},
		Role:           p.latest.Role(p.selfAccount),
		InviterAccount: p.inviterAccount,
		Members:        len(p.latest.Members),
	}, nil
}

// verifyEncBinding checks that enc_pub is signed by the account signing key
// (the keys.Account enc_pub_sig binding) so nobody can pair their own
// encryption key with someone else's identity.
func verifyEncBinding(accountPubHex, encPubHex, sigHex string) error {
	acct, err := hex.DecodeString(accountPubHex)
	if err != nil || len(acct) != ed25519.PublicKeySize {
		return errors.New("invalid account pubkey")
	}
	enc, err := hex.DecodeString(encPubHex)
	if err != nil || len(enc) != 32 {
		return errors.New("invalid encryption pubkey")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("invalid enc_pub signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(acct), enc, sig) {
		return errors.New("encryption key is not signed by the account key")
	}
	return nil
}

func decodeKey32(hexKey string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("bad key length %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}
