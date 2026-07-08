// Package daemon implements `lore serve`: the device-to-device sync engine.
// It serves the /lore/v1/* routes over agentmesh mTLS (pkg/transport),
// discovers peers over mDNS (pkg/discovery), syncs every space it shares
// with each known peer on a fixed interval (and on admin poke), exposes a
// loopback admin API, and mirrors the personal space to the distill dir.
package daemon

import (
	"context"
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
	SyncInterval time.Duration // default 30s
	Logf         func(format string, args ...any)
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

	distillDir string
	watcher    *distill.Watcher
	renderMu   sync.Mutex

	mu       sync.Mutex
	lastSync time.Time
	lastErrs []string
}

// New loads identity and store from home and prepares (but does not start)
// the daemon.
func New(home string, opts Options) (*Daemon, error) {
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = 30 * time.Second
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return nil, err
	}
	if err := device.Cert.VerifyForAccount(account.AccountID()); err != nil {
		return nil, err
	}
	priv, err := device.PrivateKey()
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
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		st.Close()
		return nil, err
	}
	cert, err := identity.FromPrivateKey(priv).TLSCertificate()
	if err != nil {
		st.Close()
		db.Close()
		return nil, err
	}
	d := &Daemon{
		home:       home,
		opts:       opts,
		account:    account,
		device:     device,
		st:         st,
		db:         db,
		cert:       cert,
		client:     transport.NewClient(cert),
		certHdr:    syncproto.EncodeDeviceCert(device.Cert),
		reg:        discovery.NewRegistry(device.DeviceID()),
		poke:       make(chan chan struct{}, 8),
		distillDir: explicitDistillDir(home),
	}
	return d, nil
}

// explicitDistillDir returns config.json's distill_dir only when it is
// explicitly configured — the daemon must never guess its way into the real
// ~/.claude/distill on a store that never opted in.
func explicitDistillDir(home string) string {
	b, err := os.ReadFile(filepath.Join(home, "config.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		DistillDir string `json:"distill_dir"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return ""
	}
	return cfg.DistillDir
}

// Start binds the sync and admin listeners, writes daemon.json, starts
// discovery, the distill watcher, and the sync loop.
func (d *Daemon) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	// mTLS sync server.
	d.server = &transport.Server{Cert: d.cert, Handler: d.syncHandler()}
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
	if d.distillDir != "" {
		if personal, err := d.st.PersonalSpace(); err == nil {
			rec, err := distill.Render(d.st, personal.SpaceID, d.distillDir)
			if err != nil {
				d.opts.Logf("distill render: %v", err)
			} else if w, err := distill.Watch(d.st, personal.SpaceID, d.distillDir, rec, 0); err != nil {
				d.opts.Logf("distill watch: %v", err)
			} else {
				d.watcher = w
			}
		}
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

// Stop shuts down listeners and loops, removes daemon.json and closes the DB.
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
	d.shutdownServers(ctx)
	d.wg.Wait()
	_ = os.Remove(filepath.Join(d.home, "daemon.json"))
	_ = d.db.Close()
	_ = d.st.Close()
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
