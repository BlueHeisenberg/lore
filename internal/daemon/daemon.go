// Package daemon implements `lore serve`: the device-to-device sync engine.
// It serves the /lore/v1/* routes over agentmesh mTLS (pkg/transport),
// discovers peers over mDNS (pkg/discovery), syncs every space it shares
// with each known peer on a fixed interval (and on admin poke), exposes a
// loopback admin API, and mirrors the personal space to the distill dir.
package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BlueHeisenberg/agentmesh/pkg/discovery"
	"github.com/BlueHeisenberg/agentmesh/pkg/identity"
	"github.com/BlueHeisenberg/agentmesh/pkg/transport"
	"github.com/BlueHeisenberg/lore/internal/distill"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// ServiceType is lore's mDNS service type.
const ServiceType = "_lore._tcp"

// Options configure a Daemon.
type Options struct {
	LAN          bool          // bind 0.0.0.0 and advertise/browse LAN interfaces
	NoMDNS       bool          // disable discovery entirely (tests, static-peer-only setups)
	AdminPort    int           // admin API port on 127.0.0.1 (0 = ephemeral)
	SyncPort     int           // fixed mTLS sync port (0 = ephemeral); required for static peers across VPNs like Tailscale, where the address must survive restarts
	SyncInterval time.Duration // default 30s

	// PeerTTL is how long a peer discovered over mDNS survives without being
	// seen — neither advertising itself nor answering a sync — before the
	// daemon forgets it. Default 1h. Static peers are never expired.
	//
	// It is a knob because the right value is a property of the deployment,
	// not of lore: on a container host a replaced pod's address is dead the
	// moment it stops advertising and an hour is generous, while a household
	// of machines that are usually off wants long enough that a laptop
	// shutting for the night is not treated as a departure. Forgetting is
	// cheap either way — mDNS rediscovers and re-verifies from scratch.
	PeerTTL time.Duration

	Logf func(format string, args ...any)
}

// Daemon is the running sync engine. Create with New, then Start; Stop
// shuts everything down and removes daemon.json.
type Daemon struct {
	home    string
	opts    Options
	account *keys.Account
	device  *keys.Device
	st      *store.Store
	db      *sql.DB
	cert    tls.Certificate
	client  *transport.Client
	certHdr string // our device cert, header-encoded

	server    *transport.Server
	admin     *http.Server
	reg       *discovery.Registry
	stopAdv   func()
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	poke      chan chan struct{}
	port      int
	adminPort int
	token     string

	mirrorDir string
	watcher   *distill.Watcher
	renderMu  sync.Mutex
	relay     *RelayRunner

	// ownStore says Stop must close st. True for New, which opened it;
	// false for NewWithStore, whose caller did and keeps using it.
	ownStore bool

	mu       sync.Mutex
	lastSync time.Time
	lastErrs []string
	common   map[string][]string // peer device id -> local space ids last seen in common
}

// New loads identity and store from home and prepares (but does not start)
// the daemon. Stop closes the store it opened.
func New(home string, opts Options) (*Daemon, error) {
	account, device, priv, err := loadIdentity(home)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID:  account.AccountID(),
		DeviceID:   device.DeviceID(),
		DevicePriv: priv,
	})
	if err != nil {
		return nil, err
	}
	d, err := newDaemon(home, st, account, device, priv, opts)
	if err != nil {
		st.Close()
		return nil, err
	}
	d.ownStore = true
	return d, nil
}

// NewWithStore prepares a daemon on a store the caller already opened on
// home, and leaves that store open when it stops: the caller owns it.
//
// It exists so an embedder runs the daemon on the same store handle it reads
// and writes through, rather than a second one on the same lore.db. The
// identity is still loaded from home — the daemon signs with the device key
// and serves mTLS with a certificate derived from it, and a store handle
// carries neither.
func NewWithStore(home string, st *store.Store, opts Options) (*Daemon, error) {
	account, device, priv, err := loadIdentity(home)
	if err != nil {
		return nil, err
	}
	return newDaemon(home, st, account, device, priv, opts)
}

// loadIdentity loads the account and device keys under home and checks that
// the device certificate chains to the account.
func loadIdentity(home string) (*keys.Account, *keys.Device, ed25519.PrivateKey, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, nil, nil, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := device.Cert.VerifyForAccount(account.AccountID()); err != nil {
		return nil, nil, nil, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	return account, device, priv, nil
}

// newDaemon wires a daemon around an open store. It opens the second
// connection sync bookkeeping needs and closes it again on any later failure;
// what it never touches is st, whose ownership is the caller's business.
func newDaemon(home string, st *store.Store, account *keys.Account, device *keys.Device,
	priv ed25519.PrivateKey, opts Options) (*Daemon, error) {
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = 30 * time.Second
	}
	if opts.PeerTTL <= 0 {
		opts.PeerTTL = time.Hour
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return nil, err
	}
	cert, err := identity.FromPrivateKey(priv).TLSCertificate()
	if err != nil {
		db.Close()
		return nil, err
	}
	d := &Daemon{
		home:      home,
		opts:      opts,
		account:   account,
		device:    device,
		st:        st,
		db:        db,
		cert:      cert,
		client:    transport.NewClient(cert),
		certHdr:   syncproto.EncodeDeviceCert(device.Cert),
		reg:       discovery.NewRegistry(device.DeviceID()),
		poke:      make(chan chan struct{}, 8),
		mirrorDir: explicitMirrorDir(home),
		common:    map[string][]string{},
	}
	return d, nil
}

// explicitMirrorDir returns config.json's mirror_dir only when it is
// explicitly configured — the daemon must never guess its way into the real
// ~/.claude/distill on a store that never opted in.
func explicitMirrorDir(home string) string {
	b, err := os.ReadFile(filepath.Join(home, "config.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		MirrorDir string `json:"mirror_dir"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return ""
	}
	return cfg.MirrorDir
}

// Start binds the sync and admin listeners, writes daemon.json, starts
// discovery, the distill watcher, and the sync loop.
func (d *Daemon) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	// mTLS sync server.
	d.server = &transport.Server{Cert: d.cert, Handler: d.syncHandler(), Port: d.opts.SyncPort}
	port, err := d.server.Start(d.opts.LAN)
	if err != nil {
		cancel()
		return fmt.Errorf("sync listener: %w", err)
	}
	d.port = port

	// Admin API on loopback.
	if err := d.startAdmin(); err != nil {
		cancel()
		d.server.Stop(context.Background())
		return err
	}
	if err := d.writeDaemonJSON(); err != nil {
		cancel()
		d.shutdownServers(context.Background())
		return err
	}

	// mDNS.
	if !d.opts.NoMDNS {
		if err := d.startDiscovery(ctx); err != nil {
			d.opts.Logf("discovery disabled: %v", err)
		}
	}

	// Distill mirror: initial render + watcher, only when configured.
	if d.mirrorDir != "" {
		if personal, err := d.st.PersonalSpace(); err == nil {
			rec, err := distill.Render(d.st, personal.SpaceID, d.mirrorDir)
			if err != nil {
				d.opts.Logf("distill render: %v", err)
			} else if w, err := distill.Watch(d.st, personal.SpaceID, d.mirrorDir, rec, 0); err != nil {
				d.opts.Logf("distill watch: %v", err)
			} else {
				d.watcher = w
			}
		}
	}

	// Relay loop (no-op unless config.json sets relay_url).
	if rr, err := StartRelay(ctx, d.home, d.opts.Logf); err != nil {
		d.opts.Logf("relay disabled: %v", err)
	} else if rr != nil {
		d.relay = rr
	}

	d.wg.Add(1)
	go d.loop(ctx)
	return nil
}

// Port returns the mTLS sync port.
func (d *Daemon) Port() int { return d.port }

// AdminPort returns the loopback admin port.
func (d *Daemon) AdminPort() int { return d.adminPort }

// Token returns the admin token (tests).
func (d *Daemon) Token() string { return d.token }

// DeviceID returns this daemon's device id.
func (d *Daemon) DeviceID() string { return d.device.DeviceID() }

// SyncNow triggers an immediate sync round and waits for it to finish or
// ctx to expire.
func (d *Daemon) SyncNow(ctx context.Context) {
	done := make(chan struct{})
	select {
	case d.poke <- done:
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Stop shuts down listeners and loops, removes daemon.json and closes the
// sync connection. The knowledge store is closed only when this daemon opened
// it (New); a store handed to NewWithStore is left open for its owner.
func (d *Daemon) Stop(ctx context.Context) {
	if d.cancel != nil {
		d.cancel()
	}
	if d.stopAdv != nil {
		d.stopAdv()
	}
	if d.watcher != nil {
		_ = d.watcher.Close()
	}
	if d.relay != nil {
		d.relay.Stop()
	}
	d.shutdownServers(ctx)
	d.wg.Wait()
	_ = os.Remove(filepath.Join(d.home, "daemon.json"))
	_ = d.db.Close()
	if d.ownStore {
		_ = d.st.Close()
	}
}

func (d *Daemon) shutdownServers(ctx context.Context) {
	if d.server != nil {
		d.server.Stop(ctx)
	}
	if d.admin != nil {
		_ = d.admin.Shutdown(ctx)
	}
}

// loop is the sync scheduler: a round every SyncInterval and on every poke.
func (d *Daemon) loop(ctx context.Context) {
	defer d.wg.Done()
	timer := time.NewTimer(0) // immediate first round
	defer timer.Stop()
	for {
		var done chan struct{}
		select {
		case <-ctx.Done():
			return
		case done = <-d.poke:
		case <-timer.C:
		}
		d.syncRound(ctx)
		if done != nil {
			close(done)
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(d.opts.SyncInterval)
	}
}

func (d *Daemon) setLastSync(errs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastSync = time.Now()
	d.lastErrs = errs
}
