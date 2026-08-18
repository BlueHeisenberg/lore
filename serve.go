package lore

import (
	"context"
	"fmt"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
)

// ServeOptions configure Serve. The zero value is what `lore serve` does with
// no flags: loopback only, mDNS discovery on, a round every thirty seconds.
type ServeOptions struct {
	// LAN binds the sync listener on 0.0.0.0 and advertises and browses on
	// LAN interfaces as well as loopback. Off — the default — is loopback
	// only, which reaches other processes on this machine and nothing else.
	// A container's siblings are not on its loopback, so a deployment of one
	// store per container needs this on.
	//
	// It widens who can open a TLS connection, not who can read anything: a
	// peer is admitted to a space only when it can already compute that
	// space's blinded id, which needs the space key.
	LAN bool

	// NoDiscovery turns mDNS off entirely. The daemon then syncs only with
	// peers already in its peers table, and is not discoverable itself. For a
	// deployment whose addresses are configured rather than found.
	NoDiscovery bool

	// SyncPort fixes the mTLS sync port; 0 takes an ephemeral one. Set it
	// when peers reach this device at an address that has to survive a
	// restart — a static peer entry across a VPN, say.
	SyncPort int

	// AdminPort fixes the loopback admin port; 0 takes an ephemeral one. The
	// port and its token are published in Home/daemon.json (0600) while the
	// daemon runs, which is how Options.NotifyOnWrite finds it.
	AdminPort int

	// SyncInterval is how often a sync round runs. Zero means 30s. A round
	// also runs immediately at start and whenever a local write pokes the
	// admin API.
	SyncInterval time.Duration

	// PeerTTL is how long a peer discovered over mDNS survives unseen before
	// it is forgotten. Zero means an hour. Peers added by address are never
	// expired. Short suits a container host, where a replaced instance's
	// address is dead as soon as it stops advertising; long suits machines
	// that are usually off.
	PeerTTL time.Duration

	// ShutdownTimeout bounds the shutdown that follows ctx being cancelled.
	// Zero means 5s. Listeners close first either way; the timeout is how
	// long a sync round in flight is given to finish.
	ShutdownTimeout time.Duration

	// Logf receives the daemon's running diagnostics — per-peer sync
	// failures, a rejected hello, a forgotten address. These are the only
	// account of why sync is not working, and there is nowhere else they go:
	// leave this nil and they are discarded rather than printed somewhere
	// this process cannot see. It is called from the daemon's own goroutines,
	// so it must be safe to call concurrently.
	Logf func(format string, args ...any)

	// Ready, when set, is called once from Serve's goroutine after the
	// listeners are bound and daemon.json is written, and never again. It is
	// the only way to learn the ephemeral ports, and it is the signal a
	// supervisor waits on before calling the daemon up.
	Ready func(ServeInfo)
}

// ServeInfo describes a daemon that has finished starting.
type ServeInfo struct {
	// DeviceID is the device this daemon syncs as: the same value as
	// (*Store).DeviceID.
	DeviceID string

	// SyncPort is the mTLS device-to-device port it is listening on.
	SyncPort int

	// AdminPort is the loopback admin port it is listening on.
	AdminPort int
}

// Serve runs the sync daemon on this store's home until ctx is cancelled.
//
// The daemon is what carries an entry from one lore home to another. Nothing
// else does: PutEntry writes locally and pokes a running daemon if there is
// one (Options.NotifyOnWrite), and a store with no daemon anywhere is a store
// whose writes never leave the machine. What it does is serve the mTLS sync
// routes, discover peers over mDNS unless told not to, and run a sync round
// on an interval and on every poke — each round a blinded space-id
// intersection with every known peer, then a pull and a push per space the
// two turn out to share.
//
// It blocks. Run it in a goroutine, cancel ctx to stop it, and wait for the
// return: by then the listeners are closed, daemon.json is removed and every
// goroutine the daemon started is gone. The store is left open — it is the
// caller's, and Serve neither opens nor closes it.
//
// # Errors
//
// Serve returns nil when ctx is cancelled and the daemon shut down, so a
// supervisor can treat any non-nil return as a genuine failure to serve. A
// non-nil error means the daemon never started: a listener that would not
// bind, an identity that would not load, ErrReadOnly on a store that cannot
// sign, ErrClosed, or ctx's own error if it was already done.
//
// Failures after that point are per-peer and per-round rather than fatal — an
// unreachable sibling is not a reason to stop syncing with the others — and
// they reach Options.Logf and GET /admin/status, not this return value.
//
// # One home, two daemons
//
// Nothing stops a second daemon starting on a home that already has one, and
// a consumer should assume it will happen: a person running `lore serve` in a
// terminal against the home an embedding process is already serving is the
// ordinary case. It is not a data hazard — both daemons hold the same store
// through SQLite's WAL and lore's busy retry, and both apply the same signed,
// last-writer-wins entries — but it is untidy in three ways worth knowing.
// The two bind different ephemeral ports and both advertise the same device
// id, so a peer's recorded address flaps between them. The second overwrites
// daemon.json, so write pokes go to it alone. And whichever stops first
// removes daemon.json, after which pokes silently reach nobody and the
// survivor syncs only on its interval.
//
// Serve does not refuse: it cannot tell a leftover file from a live daemon
// without racing, and the CLI has always allowed it. If a single daemon per
// home matters to a deployment, that is the deployment's invariant to hold.
func (s *Store) Serve(ctx context.Context, opts ServeOptions) error {
	switch {
	case s.closed.Load():
		return ErrClosed
	case s.readOnly:
		return fmt.Errorf("%w: the sync daemon signs what it applies", ErrReadOnly)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := daemon.NewWithStore(s.home, s.st, daemon.Options{
		LAN:          opts.LAN,
		NoMDNS:       opts.NoDiscovery,
		AdminPort:    opts.AdminPort,
		SyncPort:     opts.SyncPort,
		SyncInterval: opts.SyncInterval,
		PeerTTL:      opts.PeerTTL,
		Logf:         opts.Logf,
	})
	if err != nil {
		return err
	}
	if err := d.Start(); err != nil {
		return err
	}
	if opts.Ready != nil {
		opts.Ready(ServeInfo{
			DeviceID:  d.DeviceID(),
			SyncPort:  d.Port(),
			AdminPort: d.AdminPort(),
		})
	}
	<-ctx.Done()
	timeout := opts.ShutdownTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	// The caller's ctx is already cancelled; shutting down under it would
	// skip the graceful part entirely.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	d.Stop(stopCtx)
	return nil
}
