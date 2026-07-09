package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

func init() {
	register("relay", "relay status|set-url|sync-now", cmdRelay)
}

func cmdRelay(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lore relay status|set-url <url>|sync-now")
	}
	sub, rest := args[0], args[1:]
	home, err := loreHome()
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		return relayStatus(home)
	case "set-url":
		return relaySetURL(home, rest)
	case "sync-now":
		return relaySyncNow(home)
	default:
		return fmt.Errorf("unknown relay subcommand %q (status|set-url|sync-now)", sub)
	}
}

func relayStatus(home string) error {
	cfgURL := relayclient.RelayURL(home)
	if cfgURL == "" {
		fmt.Println("relay    not configured (lore relay set-url <url>, or lore signup --relay <url>)")
	} else {
		fmt.Printf("relay    %s\n", cfgURL)
	}

	// Daemon liveness via daemon.json + admin API (best effort).
	if dj, err := readDaemonJSON(home); err != nil {
		fmt.Printf("daemon   %v\n", err)
	} else {
		httpc := &http.Client{Timeout: 5 * time.Second}
		statusURL := fmt.Sprintf("http://127.0.0.1:%d/admin/status?token=%s", dj.Port, dj.Token)
		if resp, err := httpc.Get(statusURL); err != nil {
			fmt.Printf("daemon   unreachable (pid %d?): %v\n", dj.PID, err)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			fmt.Printf("daemon   running (pid %d, admin :%d)\n", dj.PID, dj.Port)
		}
	}

	// Per-space relay offsets straight from lore.db (WAL: safe alongside a
	// running daemon).
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return nil // no store yet; config info above is all there is
	}
	defer db.Close()
	spaces, err := syncproto.ListSpaceRecords(db)
	if err != nil {
		return nil
	}
	for _, sp := range spaces {
		if len(sp.SpaceKey) != 32 {
			continue
		}
		off, _ := relayclient.LogOffset(db, sp.SpaceID)
		snap, _ := relayclient.SnapUpto(db, sp.SpaceID)
		fmt.Printf("space    %-12s %-8s log_offset=%d snapshot_upto=%d\n", sp.Name, sp.Kind, off, snap)
	}
	return nil
}

func relaySetURL(home string, args []string) error {
	fs := flag.NewFlagSet("relay set-url", flag.ContinueOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore relay set-url <url>")
	}
	u, err := url.Parse(pos[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("relay URL must be http(s)://host[:port], got %q", pos[0])
	}
	// config.json is shared with other commands: SetConfigValue round-trips
	// the raw JSON map so every unknown key is preserved.
	if err := relayclient.SetRelayURL(home, pos[0]); err != nil {
		return err
	}
	fmt.Printf("ok: relay_url = %s (restart `lore serve` to apply)\n", pos[0])
	return nil
}

// relaySyncNow pokes the running daemon's admin API for an immediate sync
// round (the daemon's relay loop long-polls continuously; the poke covers
// the LAN sync engine and refreshes state promptly).
func relaySyncNow(home string) error {
	dj, err := readDaemonJSON(home)
	if err != nil {
		return err
	}
	httpc := &http.Client{Timeout: 90 * time.Second}
	resp, err := httpc.Post(
		fmt.Sprintf("http://127.0.0.1:%d/admin/sync?token=%s", dj.Port, dj.Token),
		"application/json", nil)
	if err != nil {
		return fmt.Errorf("daemon unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("admin sync: %s: %s", resp.Status, b)
	}
	fmt.Println("sync round completed")
	return nil
}
