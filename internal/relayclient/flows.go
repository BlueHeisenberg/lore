package relayclient

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
	"github.com/BlueHeisenberg/lore/internal/vault"
)

// entriesVV computes the version vector covered by a batch of entries.
func entriesVV(entries []store.Entry) syncproto.VV {
	vv := syncproto.VV{}
	for _, e := range entries {
		if e.DeviceSeq > vv[e.OriginDevice] {
			vv[e.OriginDevice] = e.DeviceSeq
		}
	}
	return vv
}

// PushSpace uploads every local entry version the relay set is not known to
// hold (relay_vv bookkeeping) as one encrypted delta, member docs included.
// Idempotent: a crash between append and the vv update only causes a
// harmless re-upload — receivers dedupe by LWW. Returns entries pushed.
func PushSpace(ctx context.Context, c *Client, db *sql.DB, sp store.Space) (int, error) {
	rvv, err := RelayVV(db, sp.SpaceID)
	if err != nil {
		return 0, err
	}
	missing, err := syncproto.EntriesSince(db, sp.SpaceID, rvv)
	if err != nil {
		return 0, err
	}
	if len(missing) == 0 {
		return 0, nil
	}
	docs, err := syncproto.MemberDocs(db, sp.SpaceID)
	if err != nil {
		return 0, err
	}
	blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)
	blob, err := EncryptDelta(sp.SpaceKey, blinded, Delta{Entries: missing, MemberDocs: docs})
	if err != nil {
		return 0, err
	}
	if _, err := c.AppendLog(ctx, blinded, blob); err != nil {
		return 0, err
	}
	if err := SetRelayVV(db, sp.SpaceID, rvv.Merge(entriesVV(missing))); err != nil {
		return len(missing), err
	}
	return len(missing), nil
}

// PullSpace catches a space up from the relay: on first contact (offset 0)
// it applies the snapshot, then reads the log tail from offset+1 (long-poll
// when wait > 0) and applies each delta through the verified receive path.
// A blob failing authenticated decryption aborts WITHOUT advancing the
// offset — corruption is surfaced, never skipped. Returns entries applied
// and the last relay seq now covered.
func PullSpace(ctx context.Context, c *Client, st *store.Store, db *sql.DB,
	sp store.Space, ownAccount string, wait time.Duration) (int, int64, error) {

	blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)
	off, err := LogOffset(db, sp.SpaceID)
	if err != nil {
		return 0, 0, err
	}
	rvv, err := RelayVV(db, sp.SpaceID)
	if err != nil {
		return 0, off, err
	}
	applied := 0

	if off == 0 {
		snap, upto, err := c.GetSnapshot(ctx, blinded)
		switch {
		case err == nil:
			d, err := DecryptDelta(sp.SpaceKey, blinded, snap)
			if err != nil {
				return 0, off, fmt.Errorf("snapshot: %w", err)
			}
			n, err := ApplyDelta(st, db, sp, d, ownAccount)
			applied += n
			if err != nil {
				return applied, off, fmt.Errorf("snapshot: %w", err)
			}
			rvv = rvv.Merge(entriesVV(d.Entries))
			off = upto
			if err := SetLogOffset(db, sp.SpaceID, off); err != nil {
				return applied, off, err
			}
			if err := SetSnapUpto(db, sp.SpaceID, upto); err != nil {
				return applied, off, err
			}
		case IsNotFound(err):
			// no snapshot yet — read the log from the beginning
		default:
			return 0, off, err
		}
	}

	items, err := c.ReadLog(ctx, blinded, off+1, wait)
	if err != nil {
		return applied, off, err
	}
	for _, it := range items {
		d, err := DecryptDelta(sp.SpaceKey, blinded, it.Data)
		if err != nil {
			return applied, off, fmt.Errorf("log seq %d: %w", it.Seq, err)
		}
		n, err := ApplyDelta(st, db, sp, d, ownAccount)
		applied += n
		if err != nil {
			return applied, off, fmt.Errorf("log seq %d: %w", it.Seq, err)
		}
		rvv = rvv.Merge(entriesVV(d.Entries))
		off = it.Seq
		if err := SetLogOffset(db, sp.SpaceID, off); err != nil {
			return applied, off, err
		}
	}
	if err := SetRelayVV(db, sp.SpaceID, rvv); err != nil {
		return applied, off, err
	}
	return applied, off, nil
}

// CompactSpace folds the space's relay log into a fresh snapshot: the FULL
// local space state (every entry version, tombstones included, plus member
// docs) encrypted exactly like a delta, uploaded with ?upto so the relay
// drops the folded prefix.
func CompactSpace(ctx context.Context, c *Client, db *sql.DB, sp store.Space, upto int64) error {
	entries, err := syncproto.AllEntries(db, sp.SpaceID)
	if err != nil {
		return err
	}
	docs, err := syncproto.MemberDocs(db, sp.SpaceID)
	if err != nil {
		return err
	}
	blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)
	blob, err := EncryptDelta(sp.SpaceKey, blinded, Delta{Entries: entries, MemberDocs: docs})
	if err != nil {
		return err
	}
	if err := c.PutSnapshot(ctx, blinded, upto, blob); err != nil {
		return err
	}
	return SetSnapUpto(db, sp.SpaceID, upto)
}

// --- signup / login flows (shared by cmd/lore and tests) ---

// Signup connects an EXISTING initialized LORE_HOME to a relay: enrolls the
// device, claims the handle, uploads the keybox (account + spaces manifest,
// wrapped under Argon2id(passphrase+recovery code)), registers every local
// space that has a key, and persists relay_url + the wrap-key cache. kdf
// zero-value means vault.DefaultKDF (tests pass small params).
func Signup(ctx context.Context, home, relayURL, handle, passphrase, recoveryCode string,
	kdf vault.KDFParams) error {

	account, err := keys.LoadAccount(home)
	if err != nil {
		return err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return err
	}
	c, err := New(relayURL, device)
	if err != nil {
		return err
	}
	if err := c.EnrollDevice(ctx, account); err != nil {
		return fmt.Errorf("enroll device: %w", err)
	}
	if err := c.ClaimHandle(ctx, handle); err != nil {
		return fmt.Errorf("claim handle %q: %w", handle, err)
	}

	payload, err := BuildKeyboxPayload(home)
	if err != nil {
		return err
	}
	wk, err := DeriveWrapKey(passphrase, recoveryCode, kdf)
	if err != nil {
		return err
	}
	envelope, err := SealKeyboxWithKey(payload, wk)
	if err != nil {
		return err
	}
	if err := c.PutKeybox(ctx, envelope); err != nil {
		return fmt.Errorf("upload keybox: %w", err)
	}
	if err := SaveWrapKey(home, wk); err != nil {
		return err
	}

	for _, sp := range payload.Spaces {
		if len(sp.SpaceKey) != 32 {
			continue
		}
		blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)
		if err := c.RegisterSpace(ctx, blinded); err != nil && !IsConflict(err) {
			return fmt.Errorf("register space %q: %w", sp.Name, err)
		} // conflict = shared space registered by another owner; fine
	}
	return SetRelayURL(home, relayURL)
}

// LoginResult summarizes what a fresh-device login restored.
type LoginResult struct {
	AccountID string
	DeviceID  string
	Spaces    int
	Entries   int // entry versions applied from relay state
}

// Login provisions a FRESH device from nothing but handle + passphrase +
// recovery code: fetches the keybox by handle (unauthenticated route),
// unwraps it locally, writes account.json, mints a new device certified by
// the account key, enrolls it, restores the spaces manifest, then pulls and
// applies every space's snapshot + log tail. When it returns, `lore search`
// works.
func Login(ctx context.Context, home, relayURL, handle, passphrase, recoveryCode,
	deviceName string, kdf vault.KDFParams) (*LoginResult, error) {

	if _, err := os.Stat(filepath.Join(home, keys.AccountFile)); err == nil {
		return nil, fmt.Errorf("refusing to log in over an existing account at %s", home)
	}

	envelope, err := FetchKeyboxByHandle(ctx, relayURL, handle)
	if err != nil {
		return nil, fmt.Errorf("fetch keybox for @%s: %w", handle, err)
	}
	payload, err := OpenKeybox(envelope, passphrase, recoveryCode)
	if err != nil {
		return nil, err
	}
	account := payload.Account

	if err := keys.SaveAccount(home, &account); err != nil {
		return nil, err
	}
	if deviceName == "" {
		deviceName = "device"
	}
	device, err := keys.GenerateDevice(deviceName, &account)
	if err != nil {
		return nil, err
	}
	if err := keys.SaveDevice(home, device); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(home, "blobs"), 0o700); err != nil {
		return nil, err
	}
	if err := SetRelayURL(home, relayURL); err != nil {
		return nil, err
	}
	// Cache a wrap key (fresh salt, same secrets) so this device's daemon
	// can also refresh the keybox manifest later.
	if wk, err := DeriveWrapKey(passphrase, recoveryCode, kdf); err == nil {
		if err := SaveWrapKey(home, wk); err != nil {
			return nil, err
		}
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
	defer st.Close()
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Restore the spaces manifest verbatim (ids + keys preserved — blinded
	// ids must match every other device of this account).
	for _, sp := range payload.Spaces {
		if err := syncproto.InsertSpaceRecord(db, sp); err != nil {
			return nil, err
		}
	}

	c, err := New(relayURL, device)
	if err != nil {
		return nil, err
	}
	if err := c.EnrollDevice(ctx, &account); err != nil {
		return nil, fmt.Errorf("enroll device: %w", err)
	}

	res := &LoginResult{AccountID: account.AccountID(), DeviceID: device.DeviceID()}
	for _, rec := range payload.Spaces {
		if len(rec.SpaceKey) != 32 {
			continue
		}
		sp, err := st.GetSpace(rec.SpaceID)
		if err != nil {
			return nil, err
		}
		blinded := syncproto.BlindSpaceID(sp.SpaceKey, sp.SpaceID)
		if err := c.RegisterSpace(ctx, blinded); err != nil && !IsConflict(err) {
			return nil, fmt.Errorf("register space %q: %w", sp.Name, err)
		}
		res.Spaces++
		// Drain the full log (no long-poll): loop until the offset stops
		// advancing (reads are batch-capped server-side, one call may not
		// return everything; "applied" can be 0 on pure-LWW-loss batches).
		prevOff := int64(-1)
		for {
			applied, off, err := PullSpace(ctx, c, st, db, sp, account.AccountID(), 0)
			res.Entries += applied
			if err != nil {
				if IsForbidden(err) {
					break // shared space whose owner has not granted us yet
				}
				return res, fmt.Errorf("pull space %q: %w", sp.Name, err)
			}
			if off == prevOff {
				break
			}
			prevOff = off
		}
	}
	return res, nil
}

// ErrNoRelay is returned by helpers that need a configured relay.
var ErrNoRelay = errors.New("no relay configured (run `lore signup --relay <url>` or `lore relay set-url <url>`)")
