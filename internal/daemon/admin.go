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
type AdminStatus struct {
	DeviceID  string           `json:"device_id"`
	AccountID string           `json:"account_id"`
	Name      string           `json:"name"`
	SyncPort  int              `json:"sync_port"`
	LastSync  string           `json:"last_sync"` // RFC3339, "" if never
	SyncErrs  []string         `json:"sync_errors,omitempty"`
	Peers     []syncproto.Peer `json:"peers"`
	Spaces    []AdminSpaceInfo `json:"spaces"`
}

// AdminSpaceInfo summarizes one space for status output.
type AdminSpaceInfo struct {
	SpaceID string `json:"space_id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Entries int    `json:"entries"`
}

func (d *Daemon) handleAdminStatus(w http.ResponseWriter, _ *http.Request) {
	st := AdminStatus{
		DeviceID:  d.device.DeviceID(),
		AccountID: d.account.AccountID(),
		Name:      d.device.Name,
		SyncPort:  d.port,
		Peers:     []syncproto.Peer{},
		Spaces:    []AdminSpaceInfo{},
	}
	d.mu.Lock()
	if !d.lastSync.IsZero() {
		st.LastSync = d.lastSync.UTC().Format(time.RFC3339)
	}
	st.SyncErrs = append([]string(nil), d.lastErrs...)
	d.mu.Unlock()

	if peers, err := syncproto.ListPeers(d.db); err == nil {
		st.Peers = peers
	}
	if sps, err := d.st.ListSpaces(); err == nil {
		for _, sp := range sps {
			es, _ := d.st.ListEntries(sp.SpaceID)
			st.Spaces = append(st.Spaces, AdminSpaceInfo{
				SpaceID: sp.SpaceID, Kind: sp.Kind, Name: sp.Name, Entries: len(es),
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
