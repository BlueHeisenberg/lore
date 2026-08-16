package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// DaemonJSON is the shape of LORE_HOME/daemon.json: how local processes
// (CLI `lore sync`, the MCP server) find and authenticate to the admin API.
// Written 0600 on start, removed on shutdown.
type DaemonJSON struct {
	Port     int    `json:"port"` // admin port on 127.0.0.1
	Token    string `json:"token"`
	SyncPort int    `json:"sync_port"` // mTLS device-to-device port
	DeviceID string `json:"device_id"`
	PID      int    `json:"pid"`
}

// startAdmin binds the loopback admin API and generates the token.
func (d *Daemon) startAdmin() error {
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		return err
	}
	d.token = hex.EncodeToString(tok)

	lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(d.opts.AdminPort)))
	if err != nil {
		return err
	}
	d.adminPort = lis.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/sync", d.withToken(d.handleAdminSync))
	mux.HandleFunc("GET /admin/status", d.withToken(d.handleAdminStatus))
	d.admin = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = d.admin.Serve(lis) }()
	return nil
}

func (d *Daemon) withToken(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("token")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(d.token)) != 1 {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// handleAdminSync triggers an immediate sync round and waits for it.
func (d *Daemon) handleAdminSync(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	d.SyncNow(ctx)
	writeJSON(w, map[string]any{"ok": true})
}

// AdminStatus is the GET /admin/status response.
//
// # What this endpoint discloses, and to whom
//
// To whom: a process on this machine that both reached 127.0.0.1 and read the
// admin token out of LORE_HOME/daemon.json (mode 0600). That caller can
// already open lore.db, which holds every space key, every entry and the
// device private key — so nothing here is a new capability. It is a
// convenience over facts the caller could compute itself.
//
// What: identity, sync health, the peers table, per-space entry and member
// counts, and per-peer the space ids the two devices turned out to share.
//
// What it deliberately does NOT do is weaken the blinded intersection that
// makes sync safe. Two stores exchange a space only when both hold its id and
// its key (HMAC(space_key, "lore-blind" || space_id)), and the wire protocol
// only ever answers an offer with a subset of it — so this daemon never
// learns of a space a peer holds and it does not, and SharedSpaces cannot
// name one. Nothing blinded is published to anyone who could not already
// unblind it, and no space key, member wrapping or entry body appears here.
type AdminStatus struct {
	DeviceID  string           `json:"device_id"`
	AccountID string           `json:"account_id"`
	Name      string           `json:"name"`
	SyncPort  int              `json:"sync_port"`
	LastSync  string           `json:"last_sync"` // RFC3339, "" if never
	SyncErrs  []string         `json:"sync_errors,omitempty"`
	Peers     []AdminPeerInfo  `json:"peers"`
	Spaces    []AdminSpaceInfo `json:"spaces"`
}

// AdminPeerInfo is a peers-table row plus what this device has observed the
// peer to share with it. The peer's own fields are inlined, so the JSON is
// what it always was with one key added.
type AdminPeerInfo struct {
	syncproto.Peer

	// SharedSpaces are the local space ids the last intersection with this
	// peer returned, sorted. Empty means "not established": either no round
	// has succeeded with this peer since the daemon started (it holds no
	// history across restarts) or the two genuinely share nothing. Peer.Static
	// and Peer.LastSeen are what say which — a peer last seen days ago has a
	// correspondingly old answer here.
	SharedSpaces []string `json:"shared_spaces"`
}

// AdminSpaceInfo summarizes one space for status output.
type AdminSpaceInfo struct {
	SpaceID string `json:"space_id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Entries int    `json:"entries"`

	// Members is the size of the latest VERIFIED member list, or 0 when the
	// space has none: the personal space always (it has no member list by
	// construction — its sharing is between devices of one account, gated on
	// the account key), and a shared space until its first member doc arrives.
	// Zero is therefore "no member list", never "no members", and it is not a
	// count this device guessed at. To answer "is this actually shared?", read
	// it together with the peers' shared_spaces, which is the observed truth.
	Members int `json:"members"`
}

func (d *Daemon) handleAdminStatus(w http.ResponseWriter, _ *http.Request) {
	st := AdminStatus{
		DeviceID:  d.device.DeviceID(),
		AccountID: d.account.AccountID(),
		Name:      d.device.Name,
		SyncPort:  d.port,
		Peers:     []AdminPeerInfo{},
		Spaces:    []AdminSpaceInfo{},
	}
	d.mu.Lock()
	if !d.lastSync.IsZero() {
		st.LastSync = d.lastSync.UTC().Format(time.RFC3339)
	}
	st.SyncErrs = append([]string(nil), d.lastErrs...)
	common := make(map[string][]string, len(d.common))
	for id, ids := range d.common {
		common[id] = ids
	}
	d.mu.Unlock()

	if peers, err := syncproto.ListPeers(d.db); err == nil {
		for _, p := range peers {
			shared := common[p.DeviceID]
			if shared == nil {
				shared = []string{}
			}
			st.Peers = append(st.Peers, AdminPeerInfo{Peer: p, SharedSpaces: shared})
		}
	}
	if sps, err := d.st.ListSpaces(); err == nil {
		for _, sp := range sps {
			es, _ := d.st.ListEntries(sp.SpaceID)
			members := 0
			if doc, ok, err := d.st.LatestMemberDoc(sp.SpaceID); err == nil && ok {
				members = len(doc.Members)
			}
			st.Spaces = append(st.Spaces, AdminSpaceInfo{
				SpaceID: sp.SpaceID, Kind: sp.Kind, Name: sp.Name,
				Entries: len(es), Members: members,
			})
		}
	}
	writeJSON(w, st)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeDaemonJSON publishes the admin endpoint for local processes.
func (d *Daemon) writeDaemonJSON() error {
	b, err := json.MarshalIndent(DaemonJSON{
		Port:     d.adminPort,
		Token:    d.token,
		SyncPort: d.port,
		DeviceID: d.device.DeviceID(),
		PID:      os.Getpid(),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(d.home, "daemon.json"), append(b, '\n'), 0o600)
}
