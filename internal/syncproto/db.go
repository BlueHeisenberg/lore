package syncproto

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/BlueHeisenberg/lore/internal/store"
	_ "modernc.org/sqlite"
)

// This file holds the raw-row accessors the sync and vault layers need but
// internal/store does not expose (peers, sync_state, member docs, version
// vectors, tombstone-inclusive entry listings, raw space rows). They open a
// second handle on lore.db — safe under WAL + busy_timeout, and the same
// posture the MCP direct-DB mode relies on. Consolidating these into
// internal/store is a Phase 4 cleanup (that file is owned by parallel work).

// OpenDB opens lore.db at path with the same pragmas internal/store uses.
func OpenDB(path string) (*sql.DB, error) {
	dsn := "file:" + url.PathEscape(filepath.ToSlash(path)) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// LocalVV computes the space's version vector from the entries we hold:
// max device_seq per origin_device.
func LocalVV(db *sql.DB, spaceID string) (VV, error) {
	rows, err := db.Query(`SELECT origin_device, MAX(device_seq) FROM entries
		WHERE space_id=? GROUP BY origin_device`, spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	vv := VV{}
	for rows.Next() {
		var dev string
		var seq int64
		if err := rows.Scan(&dev, &seq); err != nil {
			return nil, err
		}
		vv[dev] = seq
	}
	return vv, rows.Err()
}

const entryCols = `entry_id,space_id,domain,title,body,markers,confidence,origin,
	author_account,author_device,created_at,updated_at,version,device_seq,
	origin_device,signature,provenance,tombstone`

func scanEntry(rows *sql.Rows) (store.Entry, error) {
	var e store.Entry
	var markers string
	var prov sql.NullString
	var tomb int
	err := rows.Scan(&e.EntryID, &e.SpaceID, &e.Domain, &e.Title, &e.Body, &markers,
		&e.Confidence, &e.Origin, &e.AuthorAccount, &e.AuthorDevice,
		&e.CreatedAt, &e.UpdatedAt, &e.Version, &e.DeviceSeq,
		&e.OriginDevice, &e.Signature, &prov, &tomb)
	if err != nil {
		return store.Entry{}, err
	}
	if markers != "" {
		if err := json.Unmarshal([]byte(markers), &e.Markers); err != nil {
			return store.Entry{}, fmt.Errorf("entry %s markers: %w", e.EntryID, err)
		}
	}
	if len(e.Markers) == 0 {
		e.Markers = nil
	}
	if prov.Valid && prov.String != "" {
		var p store.Provenance
		if err := json.Unmarshal([]byte(prov.String), &p); err != nil {
			return store.Entry{}, fmt.Errorf("entry %s provenance: %w", e.EntryID, err)
		}
		e.Provenance = &p
	}
	e.Tombstone = tomb != 0
	return e, nil
}

func queryEntries(db *sql.DB, q string, args ...any) ([]store.Entry, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EntriesSince returns every entry version (tombstones included) in the
// space that `since` does not cover: device_seq > since[origin_device].
// Ordered by (origin_device, device_seq) for deterministic transfer.
func EntriesSince(db *sql.DB, spaceID string, since VV) ([]store.Entry, error) {
	all, err := queryEntries(db, `SELECT `+entryCols+` FROM entries
		WHERE space_id=? ORDER BY origin_device, device_seq`, spaceID)
	if err != nil {
		return nil, err
	}
	var out []store.Entry
	for _, e := range all {
		if since.Since(e.OriginDevice, e.DeviceSeq) {
			out = append(out, e)
		}
	}
	return out, nil
}

// AllEntries returns every entry of a space, tombstones included (vault dump).
func AllEntries(db *sql.DB, spaceID string) ([]store.Entry, error) {
	return queryEntries(db, `SELECT `+entryCols+` FROM entries
		WHERE space_id=? ORDER BY origin_device, device_seq`, spaceID)
}

// MemberDocs returns all member-doc versions for a space, oldest first.
func MemberDocs(db *sql.DB, spaceID string) ([]MemberDoc, error) {
	rows, err := db.Query(`SELECT version, doc, sig, signer FROM member_docs
		WHERE space_id=? ORDER BY version`, spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MemberDoc
	for rows.Next() {
		var d MemberDoc
		if err := rows.Scan(&d.Version, &d.Doc, &d.Sig, &d.Signer); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// InsertMemberDoc writes a member-doc row preserving its version (restore /
// sync receive; LWW for docs = keep highest version, INSERT OR IGNORE per
// (space, version) since versions are content-addressed by the signer chain).
func InsertMemberDoc(db *sql.DB, spaceID string, d MemberDoc) error {
	_, err := db.Exec(`INSERT OR IGNORE INTO member_docs(space_id,version,doc,sig,signer)
		VALUES(?,?,?,?,?)`, spaceID, d.Version, d.Doc, d.Sig, d.Signer)
	return err
}

// ListSpaceRecords dumps the spaces table (vault / enrollment payload).
func ListSpaceRecords(db *sql.DB) ([]SpaceRecord, error) {
	rows, err := db.Query(`SELECT space_id,kind,name,project_ref,space_key,pinned,created_at
		FROM spaces ORDER BY kind='personal' DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SpaceRecord
	for rows.Next() {
		var r SpaceRecord
		var ref sql.NullString
		var pinned int
		if err := rows.Scan(&r.SpaceID, &r.Kind, &r.Name, &ref, &r.SpaceKey, &pinned, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.ProjectRef = ref.String
		r.Pinned = pinned != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertSpaceRecord writes a spaces row verbatim, preserving the space_id and
// space_key (enrollment and restore must NOT mint new ids: blinded-id
// intersection depends on all devices sharing the same id+key).
func InsertSpaceRecord(db *sql.DB, r SpaceRecord) error {
	_, err := db.Exec(`INSERT INTO spaces(space_id,kind,name,project_ref,space_key,pinned,created_at)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(space_id) DO UPDATE SET kind=excluded.kind, name=excluded.name,
		project_ref=excluded.project_ref, space_key=excluded.space_key,
		pinned=excluded.pinned, created_at=excluded.created_at`,
		r.SpaceID, r.Kind, r.Name, r.ProjectRef, r.SpaceKey, boolInt(r.Pinned), r.CreatedAt)
	return err
}

// Peer is a peers table row: a known sync peer, pinned to its device key.
type Peer struct {
	DeviceID   string `json:"device_id"`
	AccountPub string `json:"account_pub"`
	Name       string `json:"name"`
	Addr       string `json:"addr"`
	Static     bool   `json:"static"`
	LastSeen   string `json:"last_seen"`
}

// UpsertPeer records a peer. Static peers keep their configured addr on
// conflict; discovered peers refresh addr and last_seen.
func UpsertPeer(db *sql.DB, p Peer) error {
	_, err := db.Exec(`INSERT INTO peers(device_id,account_pub,name,addr,static,last_seen)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(device_id) DO UPDATE SET
		account_pub=excluded.account_pub, name=excluded.name,
		addr=CASE WHEN peers.static=1 AND excluded.static=0 THEN peers.addr ELSE excluded.addr END,
		static=MAX(peers.static, excluded.static), last_seen=excluded.last_seen`,
		p.DeviceID, p.AccountPub, p.Name, p.Addr, boolInt(p.Static), p.LastSeen)
	return err
}

// ListPeers returns all known peers.
func ListPeers(db *sql.DB) ([]Peer, error) {
	rows, err := db.Query(`SELECT device_id,account_pub,name,addr,static,last_seen FROM peers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		var p Peer
		var acct, name, addr, seen sql.NullString
		var static int
		if err := rows.Scan(&p.DeviceID, &acct, &name, &addr, &static, &seen); err != nil {
			return nil, err
		}
		p.AccountPub, p.Name, p.Addr, p.LastSeen = acct.String, name.String, addr.String, seen.String
		p.Static = static != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// TouchPeer updates last_seen for a peer.
func TouchPeer(db *sql.DB, deviceID, ts string) error {
	_, err := db.Exec(`UPDATE peers SET last_seen=? WHERE device_id=?`, ts, deviceID)
	return err
}

// SetSyncState records the highest device_seq we know peer deviceID holds
// for a space (bookkeeping; the authoritative local VV derives from entries).
func SetSyncState(db *sql.DB, spaceID, deviceID string, maxSeq int64) error {
	_, err := db.Exec(`INSERT INTO sync_state(space_id,device_id,max_seq) VALUES(?,?,?)
		ON CONFLICT(space_id,device_id) DO UPDATE SET max_seq=MAX(sync_state.max_seq, excluded.max_seq)`,
		spaceID, deviceID, maxSeq)
	return err
}

// AttachmentRow is an attachments table row (vault manifest).
type AttachmentRow struct {
	BlobHash string `json:"blob_hash"`
	EntryID  string `json:"entry_id"`
	Filename string `json:"filename"`
	Source   string `json:"source"`
	Size     int64  `json:"size"`
}

// ListAttachments dumps the attachments table.
func ListAttachments(db *sql.DB) ([]AttachmentRow, error) {
	rows, err := db.Query(`SELECT blob_hash,entry_id,filename,source,size FROM attachments`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttachmentRow
	for rows.Next() {
		var a AttachmentRow
		if err := rows.Scan(&a.BlobHash, &a.EntryID, &a.Filename, &a.Source, &a.Size); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// InsertAttachment restores an attachments row.
func InsertAttachment(db *sql.DB, a AttachmentRow) error {
	_, err := db.Exec(`INSERT OR IGNORE INTO attachments(blob_hash,entry_id,filename,source,size)
		VALUES(?,?,?,?,?)`, a.BlobHash, a.EntryID, a.Filename, a.Source, a.Size)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
