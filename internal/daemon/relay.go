// Relay sync loop for `lore serve` — a SELF-CONTAINED unit in its own file:
// it opens its own handles on lore.db (safe under WAL, the same posture the
// MCP direct-DB mode uses) and touches no other daemon state. The parent
// wires it with one call, gated purely on config:
//
//	if rr, err := daemon.StartRelay(ctx, home, logf); err != nil {
//	    logf("relay: %v", err)
//	} else if rr != nil {
//	    defer rr.Stop() // and expose rr.Status() from /admin/status
//	}
//
// StartRelay returns (nil, nil) when config.json has no relay_url — the
// relay tier is strictly opt-in.
package daemon

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// Relay loop tuning.
const (
	relayRescanInterval = 15 * time.Second // pick up newly created spaces
	relayPollWait       = 20 * time.Second // long-poll window per round
	relayBackoffMin     = time.Second
	relayBackoffMax     = 60 * time.Second
	relayCompactAfter   = 100 // deltas past the last snapshot trigger compaction
)

// RelaySpaceStatus is per-space relay state for /admin/status.
type RelaySpaceStatus struct {
	SpaceID   string `json:"space_id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	LogOffset int64  `json:"log_offset"`
	Pushed    int64  `json:"pushed"`    // entry versions uploaded since start
	Applied   int64  `json:"applied"`   // entry versions applied since start
	LastSync  string `json:"last_sync"` // RFC3339, "" if never
	LastError string `json:"last_error,omitempty"`
}

// RelayStatus is the relay section for /admin/status.
type RelayStatus struct {
	RelayURL string             `json:"relay_url"`
	Enrolled bool               `json:"enrolled"`
	Spaces   []RelaySpaceStatus `json:"spaces"`
}

// RelayRunner runs the relay sync loops. Create with StartRelay.
type RelayRunner struct {
	home     string
	relayURL string
	logf     func(string, ...any)
	account  *keys.Account
	client   *relayclient.Client
	st       *store.Store
	db       *sql.DB

	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	enrolled bool
	running  map[string]bool // space_id -> loop started
	status   map[string]*RelaySpaceStatus
	manifest string // hash of the last keybox spaces manifest we uploaded
}

// StartRelay starts the relay client loop for home. Returns (nil, nil) when
// no relay_url is configured. The loop stops when ctx is cancelled or Stop
// is called.
func StartRelay(ctx context.Context, home string, logf func(string, ...any)) (*RelayRunner, error) {
	relayURL := relayclient.RelayURL(home)
	if relayURL == "" {
		return nil, nil
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return nil, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID: account.AccountID(), DeviceID: device.DeviceID(), DevicePriv: priv,
	})
	if err != nil {
		return nil, err
	}
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		st.Close()
		return nil, err
	}
	client, err := relayclient.New(relayURL, device)
	if err != nil {
		st.Close()
		db.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	r := &RelayRunner{
		home:     home,
		relayURL: relayURL,
		logf:     logf,
		account:  account,
		client:   client,
		st:       st,
		db:       db,
		cancel:   cancel,
		running:  map[string]bool{},
		status:   map[string]*RelaySpaceStatus{},
	}
	r.wg.Add(1)
	go r.manage(ctx)
	return r, nil
}

// Stop cancels every loop, waits for them, and closes the DB handles.
func (r *RelayRunner) Stop() {
	r.cancel()
	r.wg.Wait()
	_ = r.db.Close()
	_ = r.st.Close()
}

// Status snapshots the runner state for /admin/status.
func (r *RelayRunner) Status() RelayStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := RelayStatus{RelayURL: r.relayURL, Enrolled: r.enrolled, Spaces: []RelaySpaceStatus{}}
	for _, s := range r.status {
		out.Spaces = append(out.Spaces, *s)
	}
	return out
}

// manage is the supervisor: ensures the device is enrolled, rescans spaces
// (spawning a loop per space that has a key), and refreshes the relay
// keybox whenever the spaces manifest changes (possible without the user's
// secrets thanks to the wrap-key cache written by signup/login).
func (r *RelayRunner) manage(ctx context.Context) {
	defer r.wg.Done()
	backoff := relayBackoffMin
	timer := time.NewTimer(0) // immediate first pass
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := r.managePass(ctx); err != nil {
			r.logf("relay: %v", err)
			timer.Reset(backoff)
			backoff = min(backoff*2, relayBackoffMax)
			continue
		}
		backoff = relayBackoffMin
		timer.Reset(relayRescanInterval)
	}
}

func (r *RelayRunner) managePass(ctx context.Context) error {
	r.mu.Lock()
	enrolled := r.enrolled
	r.mu.Unlock()
	if !enrolled {
		if err := r.client.EnrollDevice(ctx, r.account); err != nil {
			return fmt.Errorf("enroll: %w", err)
		}
		r.mu.Lock()
		r.enrolled = true
		r.mu.Unlock()
	}

	spaces, err := r.st.ListSpaces()
	if err != nil {
		return err
	}
	for _, sp := range spaces {
		if len(sp.SpaceKey) != 32 {
			continue // no key -> nothing can be encrypted for the relay
		}
		r.mu.Lock()
		started := r.running[sp.SpaceID]
		if !started {
			r.running[sp.SpaceID] = true
			r.status[sp.SpaceID] = &RelaySpaceStatus{SpaceID: sp.SpaceID, Name: sp.Name, Kind: sp.Kind}
		}
		r.mu.Unlock()
		if !started {
			r.wg.Add(1)
			go r.spaceLoop(ctx, sp)
		}
	}
	return r.refreshKeybox(ctx)
}

// refreshKeybox re-uploads the keybox when the spaces manifest changed, so
// a later fresh-device `lore login` discovers spaces created after signup.
// Requires the wrap-key cache (LORE_HOME/keybox.key); without it — e.g. the
// user never ran `lore signup` from this home — it silently no-ops (the
// daemon never holds the passphrase or recovery code).
func (r *RelayRunner) refreshKeybox(ctx context.Context) error {
	wk, err := relayclient.LoadWrapKey(r.home)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	payload, err := relayclient.BuildKeyboxPayload(r.home)
	if err != nil {
		return err
	}
	mb, err := json.Marshal(payload.Spaces)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(mb)
	manifest := hex.EncodeToString(sum[:])
	r.mu.Lock()
	unchanged := manifest == r.manifest
	r.mu.Unlock()
	if unchanged {
		return nil
	}
	envelope, err := relayclient.SealKeyboxWithKey(payload, wk)
	if err != nil {
		return err
	}
	if err := r.client.PutKeybox(ctx, envelope); err != nil {
		return fmt.Errorf("refresh keybox: %w", err)
	}
	r.mu.Lock()
	r.manifest = manifest
	r.mu.Unlock()
	r.logf("relay: keybox refreshed (%d spaces)", len(payload.Spaces))
	return nil
}

// spaceLoop is one space's push + long-poll-pull + compaction cycle with
// exponential backoff on errors (1s -> 60s cap).
func (r *RelayRunner) spaceLoop(ctx context.Context, sp store.Space) {
	defer r.wg.Done()
	blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)
	backoff := relayBackoffMin
	registered := false
	for ctx.Err() == nil {
		err := func() error {
			if !registered {
				if err := r.client.RegisterSpace(ctx, blinded); err != nil && !relayclient.IsConflict(err) {
					return fmt.Errorf("register: %w", err)
				} // conflict: owned by another account (shared space) — proceed on granted access
				registered = true
			}

			pushed, err := relayclient.PushSpace(ctx, r.client, r.db, sp)
			if err != nil {
				return fmt.Errorf("push: %w", err)
			}

			applied, lastSeq, err := relayclient.PullSpace(ctx, r.client, r.st, r.db, sp,
				r.account.AccountID(), relayPollWait)
			if err != nil {
				return fmt.Errorf("pull: %w", err)
			}

			// Compaction: fold the log into a snapshot once it outgrows the
			// threshold past the last snapshot we know of.
			snapUpto, err := relayclient.SnapUpto(r.db, sp.SpaceID)
			if err != nil {
				return err
			}
			if lastSeq-snapUpto > relayCompactAfter {
				if err := relayclient.CompactSpace(ctx, r.client, r.db, sp, lastSeq); err != nil {
					return fmt.Errorf("compact: %w", err)
				}
				r.logf("relay: compacted %s upto seq %d", sp.Name, lastSeq)
			}

			r.updateStatus(sp.SpaceID, func(s *RelaySpaceStatus) {
				s.LogOffset = lastSeq
				s.Pushed += int64(pushed)
				s.Applied += int64(applied)
				s.LastSync = time.Now().UTC().Format(time.RFC3339)
				s.LastError = ""
			})
			return nil
		}()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			r.updateStatus(sp.SpaceID, func(s *RelaySpaceStatus) { s.LastError = err.Error() })
			r.logf("relay: space %s: %v", sp.Name, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, relayBackoffMax)
			continue
		}
		backoff = relayBackoffMin
		// No idle sleep needed: PullSpace long-polled relayPollWait, so each
		// healthy round is naturally paced and wakes instantly on remote
		// appends; local writes ride the next round (<= relayPollWait away).
	}
}

func (r *RelayRunner) updateStatus(spaceID string, f func(*RelaySpaceStatus)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.status[spaceID]; ok {
		f(s)
	}
}
