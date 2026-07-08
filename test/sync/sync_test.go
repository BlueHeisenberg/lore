// Package sync_test is the Phase 3 integration test: two LORE_HOMEs, LAN
// enrollment (loopback, no mDNS), two daemons wired as static peers, and a
// full put -> sync -> delete -> tombstone-sync round trip.
package sync_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

// initHome does what `lore init` does, minus prompts: account + device +
// personal space. Returns the personal space.
func initHome(t *testing.T, home, deviceName string) store.Space {
	t.Helper()
	account, err := keys.GenerateAccount()
	if err != nil {
		t.Fatal(err)
	}
	device, err := keys.GenerateDevice(deviceName, account)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveAccount(home, account); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveDevice(home, device); err != nil {
		t.Fatal(err)
	}
	st := openStore(t, home)
	key, err := space.NewSpaceKey()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := st.CreateSpace("personal", "personal", "", key)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// openStore opens a signing store handle on home (extra WAL connection
// alongside the daemon's own, same as the CLI does).
func openStore(t *testing.T, home string) *store.Store {
	t.Helper()
	account, err := keys.LoadAccount(home)
	if err != nil {
		t.Fatal(err)
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := device.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID: account.AccountID(), DeviceID: device.DeviceID(), DevicePriv: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// waitFor polls cond until it returns nil or the deadline passes.
func waitFor(t *testing.T, d *daemon.Daemon, deadline time.Duration, what string, cond func() error) {
	t.Helper()
	stop := time.Now().Add(deadline)
	var last error
	for time.Now().Before(stop) {
		if last = cond(); last == nil {
			return
		}
		// keep rounds coming faster than the interval
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		d.SyncNow(ctx)
		cancel()
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

func startDaemon(t *testing.T, home string) *daemon.Daemon {
	t.Helper()
	d, err := daemon.New(home, daemon.Options{
		NoMDNS:       true,
		SyncInterval: 2 * time.Second,
		Logf:         t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.Stop(ctx)
	})
	return d
}

func TestTwoDeviceEnrollAndSync(t *testing.T) {
	homeA := filepath.Join(t.TempDir(), "a")
	homeB := filepath.Join(t.TempDir(), "b")

	// Device A: fresh account.
	personal := initHome(t, homeA, "device-a")

	// Enroll device B from A over loopback (no mDNS in tests: explicit addr).
	enrollee, err := daemon.StartEnrollee(homeB, "device-b", false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer enrollee.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	newDev, err := daemon.Approve(ctx, homeA, enrollee.Code,
		fmt.Sprintf("127.0.0.1:%d", enrollee.Port))
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := enrollee.Wait(ctx); err != nil {
		t.Fatalf("enrollee: %v", err)
	}

	// B got the account and the personal space verbatim.
	devB, err := keys.LoadDevice(homeB)
	if err != nil {
		t.Fatal(err)
	}
	if devB.DeviceID() != newDev {
		t.Fatalf("approve returned %s, device.json has %s", newDev, devB.DeviceID())
	}
	acctA, _ := keys.LoadAccount(homeA)
	if err := devB.Cert.VerifyForAccount(acctA.AccountID()); err != nil {
		t.Fatalf("B's device cert must chain to A's account: %v", err)
	}
	stB := openStore(t, homeB)
	spB, err := stB.PersonalSpace()
	if err != nil {
		t.Fatalf("B personal space: %v", err)
	}
	if spB.SpaceID != personal.SpaceID {
		t.Fatalf("personal space id differs: A=%s B=%s", personal.SpaceID, spB.SpaceID)
	}

	// Start both daemons (static peers, no mDNS) and pin each other (TOFU).
	dA := startDaemon(t, homeA)
	dB := startDaemon(t, homeB)
	if _, err := daemon.AddStaticPeer(homeA, fmt.Sprintf("127.0.0.1:%d", dB.Port())); err != nil {
		t.Fatalf("A pins B: %v", err)
	}
	if _, err := daemon.AddStaticPeer(homeB, fmt.Sprintf("127.0.0.1:%d", dA.Port())); err != nil {
		t.Fatalf("B pins A: %v", err)
	}

	// Write on A -> appears on B.
	stA := openStore(t, homeA)
	entry, err := stA.PutEntry(store.PutParams{
		SpaceID: personal.SpaceID, Domain: "ops/deploy", Title: "Deploy rule",
		Body: "deploy only from main", Markers: []string{"[NON-NEGOTIABLE]"},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, dA, 15*time.Second, "entry to reach B", func() error {
		got, err := stB.GetEntry(entry.EntryID)
		if err != nil {
			return err
		}
		if got.Body != entry.Body || got.Signature != entry.Signature {
			return errors.New("entry content differs on B")
		}
		return nil
	})

	// Delete on B -> tombstone appears on A.
	if err := stB.DeleteEntry(entry.EntryID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, dB, 15*time.Second, "tombstone to reach A", func() error {
		got, err := stA.GetEntry(entry.EntryID)
		if err != nil {
			return err
		}
		if !got.Tombstone {
			return errors.New("not yet tombstoned on A")
		}
		return nil
	})
}
