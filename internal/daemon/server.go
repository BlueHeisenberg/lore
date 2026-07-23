package daemon

import (
	"encoding/json"
	"net/http"

	"github.com/BlueHeisenberg/agentmesh/pkg/transport"
	"github.com/BlueHeisenberg/lore/internal/distill"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// syncHandler builds the /lore/v1/* mTLS routes. Every request passes the
// app-layer identity check: the TLS peer pubkey (already proven by the mTLS
// handshake) must be accompanied by an X-Lore-Device-Cert header whose cert
// verifies and names that exact device key — proving the peer is a device
// of cert.AccountPub. Personal-space operations additionally require that
// account to be our own.
func (d *Daemon) syncHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /lore/v1/hello", d.withSender(d.handleHello))
	mux.HandleFunc("POST /lore/v1/spaces", d.withSender(d.handleSpaces))
	mux.HandleFunc("POST /lore/v1/sync", d.withSender(d.handleSync))
	mux.HandleFunc("POST /lore/v1/entries", d.withSender(d.handleEntries))
	return mux
}

type senderHandler func(w http.ResponseWriter, r *http.Request, sender keys.DeviceCert)

func (d *Daemon) withSender(h senderHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cert, err := syncproto.SenderCert(r, transport.PeerIDFromConn(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		h(w, r, cert)
	}
}

func (d *Daemon) handleHello(w http.ResponseWriter, _ *http.Request, _ keys.DeviceCert) {
	transport.WriteJSON(w, http.StatusOK, syncproto.Hello{
		DeviceID:   d.device.DeviceID(),
		AccountID:  d.account.AccountID(),
		Name:       d.device.Name,
		Version:    syncproto.ProtocolVersion,
		DeviceCert: d.device.Cert,
	})
}

// blindedSpaces maps blinded id -> space for every local space the sender's
// account may sync: shared spaces always (matching requires the space key
// anyway), the personal space only for our own account's devices.
func (d *Daemon) blindedSpaces(senderAccount string) (map[string]store.Space, error) {
	sps, err := d.st.ListSpaces()
	if err != nil {
		return nil, err
	}
	out := make(map[string]store.Space, len(sps))
	for _, sp := range sps {
		if sp.Kind == "personal" && senderAccount != d.account.AccountID() {
			continue
		}
		out[syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)] = sp
	}
	return out, nil
}

func (d *Daemon) handleSpaces(w http.ResponseWriter, r *http.Request, sender keys.DeviceCert) {
	var req syncproto.SpacesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mine, err := d.blindedSpaces(sender.AccountPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := syncproto.SpacesResponse{Blinded: []string{}}
	for _, b := range req.Blinded {
		if _, ok := mine[b]; ok {
			resp.Blinded = append(resp.Blinded, b)
		}
	}
	transport.WriteJSON(w, http.StatusOK, resp)
}

// resolveBlinded maps a blinded id to a local space, enforcing the
// personal-space account gate. Returns ok=false after writing the error.
func (d *Daemon) resolveBlinded(w http.ResponseWriter, blinded string, sender keys.DeviceCert) (store.Space, bool) {
	mine, err := d.blindedSpaces(sender.AccountPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return store.Space{}, false
	}
	sp, ok := mine[blinded]
	if !ok {
		// Personal space blinded ids are excluded for foreign accounts above,
		// so a foreign device probing our personal space also lands here.
		http.Error(w, "unknown space", http.StatusNotFound)
		return store.Space{}, false
	}
	return sp, true
}

func (d *Daemon) handleSync(w http.ResponseWriter, r *http.Request, sender keys.DeviceCert) {
	var req syncproto.SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sp, ok := d.resolveBlinded(w, req.BlindedSpaceID, sender)
	if !ok {
		return
	}
	vv, err := syncproto.LocalVV(d.db, sp.SpaceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entries, err := syncproto.EntriesSince(d.db, sp.SpaceID, req.VV)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	docs, err := syncproto.MemberDocs(d.db, sp.SpaceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []store.Entry{}
	}
	if docs == nil {
		docs = []syncproto.MemberDoc{}
	}
	// Bookkeeping: the caller told us what it has seen.
	for dev, seq := range req.VV {
		_ = syncproto.SetSyncState(d.db, sp.SpaceID, dev, seq)
	}
	transport.WriteJSON(w, http.StatusOK, syncproto.SyncResponse{VV: vv, Entries: entries, MemberDocs: docs})
}

func (d *Daemon) handleEntries(w http.ResponseWriter, r *http.Request, sender keys.DeviceCert) {
	var req syncproto.EntriesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sp, ok := d.resolveBlinded(w, req.BlindedSpaceID, sender)
	if !ok {
		return
	}
	// Member docs first: entry application is judged against the verified
	// member list, which may arrive in this very request.
	if err := syncproto.MergeMemberDocs(d.db, sp.SpaceID, req.MemberDocs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	applied, err := syncproto.ApplyEntries(d.st, sp, req.Entries,
		syncproto.MemberDocCheck(d.db, d.account.AccountID()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if applied > 0 {
		for _, e := range req.Entries {
			_ = syncproto.SetSyncState(d.db, sp.SpaceID, e.OriginDevice, e.DeviceSeq)
		}
		if sp.Kind == "personal" {
			d.renderDistill()
		}
	}
	transport.WriteJSON(w, http.StatusOK, syncproto.EntriesResponse{Applied: applied})
}

// renderDistill mirrors the personal space to the distill dir after remote
// applies. Errors are logged and ignored: the mirror is a convenience view.
// The watcher's re-import of rendered files is a no-op because import skips
// files whose body already matches the entry.
func (d *Daemon) renderDistill() {
	if d.mirrorDir == "" {
		return
	}
	d.renderMu.Lock()
	defer d.renderMu.Unlock()
	personal, err := d.st.PersonalSpace()
	if err != nil {
		return
	}
	if _, err := distill.Render(d.st, personal.SpaceID, d.mirrorDir); err != nil {
		d.opts.Logf("distill render: %v", err)
	}
}
