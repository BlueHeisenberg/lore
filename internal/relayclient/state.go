package relayclient

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

// Client-side relay bookkeeping, stored in lore.db (schema owned by
// internal/store; this file only reads/writes the relay_state table and
// namespaced kv keys — no schema changes):
//
//   - relay_state.log_offset: highest relay log seq this device has applied
//     for a space. Reads resume at offset+1 (long-poll `from` semantics).
//   - kv "relay_vv:<space_id>": version vector of entry versions known to be
//     IN the relay log/snapshot (merged from every delta we upload or
//     download). Push = EntriesSince(local, relay_vv) — idempotent by
//     construction: re-uploads are harmless because receivers dedupe via LWW.
//   - kv "relay_snap_upto:<space_id>": the log seq the last snapshot this
//     device knows about covers; drives the >100-deltas compaction trigger.

// LogOffset returns the applied relay log offset for a space (0 = never).
func LogOffset(db *sql.DB, spaceID string) (int64, error) {
	var off int64
	err := db.QueryRow(`SELECT log_offset FROM relay_state WHERE space_id=?`, spaceID).Scan(&off)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return off, err
}

// SetLogOffset records the applied relay log offset for a space.
func SetLogOffset(db *sql.DB, spaceID string, offset int64) error {
	_, err := db.Exec(`INSERT INTO relay_state(space_id, log_offset) VALUES(?,?)
		ON CONFLICT(space_id) DO UPDATE SET log_offset=excluded.log_offset`, spaceID, offset)
	return err
}

func kvGet(db *sql.DB, k string) (string, error) {
	var v string
	err := db.QueryRow(`SELECT v FROM kv WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func kvSet(db *sql.DB, k, v string) error {
	_, err := db.Exec(`INSERT INTO kv(k,v) VALUES(?,?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// RelayVV returns the version vector of entries known to be on the relay.
func RelayVV(db *sql.DB, spaceID string) (syncproto.VV, error) {
	s, err := kvGet(db, "relay_vv:"+spaceID)
	if err != nil || s == "" {
		return syncproto.VV{}, err
	}
	var vv syncproto.VV
	if err := json.Unmarshal([]byte(s), &vv); err != nil {
		return syncproto.VV{}, fmt.Errorf("relay_vv:%s: %w", spaceID, err)
	}
	return vv, nil
}

// SetRelayVV stores the relay-held version vector for a space.
func SetRelayVV(db *sql.DB, spaceID string, vv syncproto.VV) error {
	b, err := json.Marshal(vv)
	if err != nil {
		return err
	}
	return kvSet(db, "relay_vv:"+spaceID, string(b))
}

// SnapUpto returns the log seq covered by the last known snapshot (0 = none).
func SnapUpto(db *sql.DB, spaceID string) (int64, error) {
	s, err := kvGet(db, "relay_snap_upto:"+spaceID)
	if err != nil || s == "" {
		return 0, err
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, nil
	}
	return n, nil
}

// SetSnapUpto records the seq covered by the latest snapshot.
func SetSnapUpto(db *sql.DB, spaceID string, upto int64) error {
	return kvSet(db, "relay_snap_upto:"+spaceID, fmt.Sprint(upto))
}
