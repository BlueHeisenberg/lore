package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
)

func init() { register("sync", "poke the running daemon for an immediate sync round", cmdSync) }

// readDaemonJSON loads LORE_HOME/daemon.json, erroring clearly when the
// daemon is not running.
func readDaemonJSON(home string) (daemon.DaemonJSON, error) {
	var dj daemon.DaemonJSON
	b, err := os.ReadFile(filepath.Join(home, "daemon.json"))
	if errors.Is(err, os.ErrNotExist) {
		return dj, errors.New("daemon not running (no daemon.json; start it with `lore serve`)")
	}
	if err != nil {
		return dj, err
	}
	if err := json.Unmarshal(b, &dj); err != nil {
		return dj, fmt.Errorf("daemon.json: %w", err)
	}
	return dj, nil
}

func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	// --now is the only mode v1 supports; accepted for CLI-contract stability.
	_ = fs.Bool("now", true, "run the round immediately (default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	dj, err := readDaemonJSON(home)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/admin/sync?token=%s", dj.Port, dj.Token)
	httpc := &http.Client{Timeout: 90 * time.Second}
	resp, err := httpc.Post(url, "application/json", nil)
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
