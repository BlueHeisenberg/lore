// Package serve_test exercises the embeddable sync daemon — lore.(*Store).Serve
// — the way a consumer runs it: in-process, in a goroutine, on a store the
// consumer opened, stopped by cancelling a context. No lore binary is executed
// anywhere in this file, which is the whole point of the API under test.
package serve_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BlueHeisenberg/lore"
	"github.com/BlueHeisenberg/lore/internal/daemon"
)

// tick is the sync interval these tests run at. Real deployments use thirty
// seconds; a test that waited that long would be replaced by a sleep.
const tick = 300 * time.Millisecond

// openHome initialises a lore home and opens a store on it.
func openHome(t *testing.T, name string) *lore.Store {
	t.Helper()
	home := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := lore.Init(home, name); err != nil {
		t.Fatalf("init %s: %v", name, err)
	}
	return openStore(t, home)
}

func openStore(t *testing.T, home string) *lore.Store {
	t.Helper()
	st, err := lore.Open(lore.Options{Home: home})
	if err != nil {
		t.Fatalf("open %s: %v", home, err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// enroll gives a second home the first home's account and personal space, the
// way `lore enroll` / `lore approve` do. Two homes only ever sync a space both
// already hold, so a convergence test needs this and the public API — which
// exposes no join — cannot provide it.
func enroll(t *testing.T, from *lore.Store, name string) *lore.Store {
	t.Helper()
	home := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	enrollee, err := daemon.StartEnrollee(home, name, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer enrollee.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := daemon.Approve(ctx, from.Home(), enrollee.Code,
		fmt.Sprintf("127.0.0.1:%d", enrollee.Port)); err != nil {
		t.Fatalf("approve %s: %v", name, err)
	}
	if err := enrollee.Wait(ctx); err != nil {
		t.Fatalf("enrollee %s: %v", name, err)
	}
	return openStore(t, home)
}

// served is a daemon running under Serve in this process.
type served struct {
	info lore.ServeInfo
	stop func() error // cancels and waits for Serve to return
}

// serve starts st.Serve in a goroutine and blocks until it reports ready.
func serve(t *testing.T, st *lore.Store, opts lore.ServeOptions) served {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan lore.ServeInfo, 1)
	done := make(chan error, 1)
	opts.SyncInterval = tick
	opts.Logf = t.Logf
	opts.Ready = func(info lore.ServeInfo) { ready <- info }
	go func() { done <- st.Serve(ctx, opts) }()

	var s served
	select {
	case info := <-ready:
		s.info = info
	case err := <-done:
		cancel()
		t.Fatalf("Serve returned before it was ready: %v", err)
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("Serve never became ready")
	}
	stopped := false
	s.stop = func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			return errors.New("Serve did not return within 20s of cancellation")
		}
	}
	t.Cleanup(func() {
		if err := s.stop(); err != nil {
			t.Errorf("stop: %v", err)
		}
	})
	return s
}

// waitFor polls cond until it passes or the deadline expires.
func waitFor(t *testing.T, deadline time.Duration, what string, cond func() error) {
	t.Helper()
	stop := time.Now().Add(deadline)
	var last error
	for time.Now().Before(stop) {
		if last = cond(); last == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

// TestServeConvergesBetweenTwoStoresInProcess is the premise of the API: two
// stores, two daemons, one process, no lore binary — and an entry written
// through the public API on one store turns up on the other. Discovery is
// left on and no peer address is configured anywhere, so finding each other
// over mDNS is part of what is asserted.
func TestServeConvergesBetweenTwoStoresInProcess(t *testing.T) {
	ctx := context.Background()
	a := openHome(t, "a")
	b := enroll(t, a, "b")

	sa := serve(t, a, lore.ServeOptions{})
	sb := serve(t, b, lore.ServeOptions{})
	if sa.info.SyncPort == 0 || sa.info.AdminPort == 0 {
		t.Fatalf("ServeInfo has no ports: %+v", sa.info)
	}
	if sa.info.DeviceID != a.DeviceID() || sb.info.DeviceID != b.DeviceID() {
		t.Fatalf("ServeInfo device ids %s/%s, stores say %s/%s",
			sa.info.DeviceID, sb.info.DeviceID, a.DeviceID(), b.DeviceID())
	}

	personal, err := a.PersonalSpace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	written, err := a.PutEntry(ctx, lore.PutParams{
		SpaceID: personal.ID, Domain: "ops/deploy", Title: "Deploy rule",
		Body: "deploy only from main",
	})
	if err != nil {
		t.Fatal(err)
	}

	waitFor(t, 60*time.Second, "the entry to reach B", func() error {
		got, err := b.GetEntry(ctx, written.ID)
		if err != nil {
			return err
		}
		if got.Body != written.Body {
			return fmt.Errorf("body on B is %q", got.Body)
		}
		return nil
	})

	// The peer was found, not configured: nothing in this test ever wrote an
	// address, so B's daemon can only have learned A's from mDNS.
	if err := sb.stop(); err != nil {
		t.Fatal(err)
	}
	if err := sa.stop(); err != nil {
		t.Fatal(err)
	}
	// Serve does not close the caller's store.
	if _, err := a.PersonalSpace(ctx); err != nil {
		t.Errorf("store A unusable after Serve returned: %v", err)
	}
}

// TestCLIDaemonAndServeAreOneEngine syncs a store served by lore.Serve
// against one served the way `lore serve` serves it — daemon.New, the CLI's
// own constructor, with the CLI's own defaults. If the embeddable path were a
// second implementation of the sync daemon rather than the same one, this is
// where the two would fail to agree: the entry would not cross.
//
// The seam between them is ownership of the store and nothing else. That is
// asserted here too: the daemon the CLI builds closes the store it opened,
// and the daemon Serve builds leaves the caller's open.
func TestCLIDaemonAndServeAreOneEngine(t *testing.T) {
	ctx := context.Background()
	a := openHome(t, "a")
	b := enroll(t, a, "b")

	sa := serve(t, a, lore.ServeOptions{})

	// B, exactly as cmd/lore/serve.go starts it.
	db, err := daemon.New(b.Home(), daemon.Options{SyncInterval: tick, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		db.Stop(stopCtx)
	}()

	personal, err := a.PersonalSpace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	written, err := a.PutEntry(ctx, lore.PutParams{
		SpaceID: personal.ID, Domain: "ops/deploy", Title: "Deploy rule",
		Body: "the CLI daemon and the library daemon are the same daemon",
	})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 60*time.Second, "the entry to cross from Serve to the CLI's daemon", func() error {
		got, err := b.GetEntry(ctx, written.ID)
		if err != nil {
			return err
		}
		if got.Body != written.Body {
			return fmt.Errorf("body on B is %q", got.Body)
		}
		return nil
	})

	if err := sa.stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PersonalSpace(ctx); err != nil {
		t.Errorf("Serve closed the caller's store: %v", err)
	}
}

// TestServeStopsOnCancellationWithoutLeaking: a consumer starts and stops
// daemons over a process's life, so "stopped" has to mean stopped —
// listeners closed, daemon.json gone, no goroutines left behind.
func TestServeStopsOnCancellationWithoutLeaking(t *testing.T) {
	st := openHome(t, "a")
	base := daemonGoroutines()

	for i := range 3 {
		s := serve(t, st, lore.ServeOptions{})
		daemonFile := filepath.Join(st.Home(), "daemon.json")
		if _, err := os.Stat(daemonFile); err != nil {
			t.Fatalf("round %d: daemon.json missing while serving: %v", i, err)
		}
		if err := s.stop(); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if _, err := os.Stat(daemonFile); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("round %d: daemon.json survived shutdown (%v)", i, err)
		}
		// Serve's own goroutines are gone the moment it returns; the mDNS
		// library's inner query loop takes a beat longer to notice its
		// context, and lore does not own it. What must not happen is a
		// goroutine per start/stop cycle accumulating, which is what this
		// catches: the count has to come back to where it began, three times
		// running, not merely stay small.
		waitFor(t, 15*time.Second, fmt.Sprintf("round %d's goroutines to exit", i), func() error {
			if n := daemonGoroutines(); n > base {
				return fmt.Errorf("%d daemon goroutines still running after Serve returned (baseline %d)\n%s",
					n, base, daemonStacks())
			}
			return nil
		})
	}

	// The store is still the caller's: usable after three daemons have come
	// and gone on it.
	if _, err := st.PersonalSpace(context.Background()); err != nil {
		t.Errorf("store unusable after Serve returned: %v", err)
	}
}

// daemonGoroutines counts goroutines whose stack names lore's daemon or the
// discovery library it starts. Counting every goroutine in the process would
// measure the test framework and net/http's idle connection reapers; this
// counts the ones Serve is responsible for.
func daemonGoroutines() int {
	n := 0
	for _, g := range strings.Split(daemonStacks(), "\n\n") {
		if strings.Contains(g, "lore/internal/daemon") || strings.Contains(g, "zeroconf") {
			n++
		}
	}
	return n
}

func daemonStacks() string {
	buf := make([]byte, 1<<20)
	return string(buf[:runtime.Stack(buf, true)])
}

// TestTwoDaemonsOnOneHome pins down what the second daemon on a home does,
// because a consumer cannot prevent a person running `lore serve` by hand
// against the home it is already serving. Both run; the second owns
// daemon.json; whichever stops first takes daemon.json with it, which is what
// silently ends write pokes to the survivor. Serve documents this rather than
// refusing, and this test is the documentation being true.
func TestTwoDaemonsOnOneHome(t *testing.T) {
	st := openHome(t, "a")
	daemonFile := filepath.Join(st.Home(), "daemon.json")

	first := serve(t, st, lore.ServeOptions{})
	second := serve(t, st, lore.ServeOptions{})

	if first.info.SyncPort == second.info.SyncPort || first.info.AdminPort == second.info.AdminPort {
		t.Fatalf("the two daemons share a port: %+v %+v", first.info, second.info)
	}
	published := readDaemonJSON(t, daemonFile)
	if published != second.info.AdminPort {
		t.Errorf("daemon.json names admin port %d; the second daemon to start is on %d",
			published, second.info.AdminPort)
	}

	// The first to stop removes the file the survivor is still named in.
	if err := first.stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(daemonFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("daemon.json survived the first daemon's shutdown (%v); "+
			"Serve's doc comment says it does not", err)
	}
	if err := second.stop(); err != nil {
		t.Fatal(err)
	}
}

func readDaemonJSON(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d.Port
}
