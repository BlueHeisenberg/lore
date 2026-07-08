package store

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// tsFormat is RFC3339 with fixed-width nanoseconds (UTC): lexicographic
// order equals chronological order, as the LWW rule requires.
const tsFormat = "2006-01-02T15:04:05.000000000Z07:00"

func tsNow() string { return time.Now().UTC().Format(tsFormat) }

// Valid enum values.
var (
	Confidences = []string{"experimental", "provisional", "validated", "hardened"}
	Origins     = []string{"evidence", "directive", "convention", "constraint"}
)

// Provenance records where a copied-out entry came from.
type Provenance struct {
	SourceEntry string `json:"source_entry"`
	SourceSpace string `json:"source_space"`
	CopiedAt    string `json:"copied_at"`
}

// Entry is the unit of knowledge; see docs/IMPLEMENTATION.md for the schema.
type Entry struct {
	EntryID       string
	SpaceID       string
	Domain        string
	Title         string
	Body          string
	Markers       []string
	Confidence    string
	Origin        string
	AuthorAccount string
	AuthorDevice  string
	CreatedAt     string
	UpdatedAt     string
	Version       int64
	DeviceSeq     int64
	OriginDevice  string
	Signature     string
	Provenance    *Provenance
	Tombstone     bool
}

// canonicalEntry pins the signing encoding: JSON with keys sorted (struct
// declaration order below IS the sorted order), no insignificant whitespace.
// Fields per contract: entry_id, space_id, domain, title, body, markers,
// confidence, origin, author_account, created_at, updated_at, version,
// device_seq, origin_device, tombstone, attachment hashes.
type canonicalEntry struct {
	Attachments   []string `json:"attachments"`
	AuthorAccount string   `json:"author_account"`
	Body          string   `json:"body"`
	Confidence    string   `json:"confidence"`
	CreatedAt     string   `json:"created_at"`
	DeviceSeq     int64    `json:"device_seq"`
	Domain        string   `json:"domain"`
	EntryID       string   `json:"entry_id"`
	Markers       []string `json:"markers"`
	Origin        string   `json:"origin"`
	OriginDevice  string   `json:"origin_device"`
	SpaceID       string   `json:"space_id"`
	Title         string   `json:"title"`
	Tombstone     bool     `json:"tombstone"`
	UpdatedAt     string   `json:"updated_at"`
	Version       int64    `json:"version"`
}

// CanonicalBytes returns the canonical signing encoding of an entry.
// attachments is the sorted list of attachment blob hashes (none in Phase 1).
func CanonicalBytes(e Entry, attachments []string) ([]byte, error) {
	if attachments == nil {
		attachments = []string{}
	}
	m := e.Markers
	if m == nil {
		m = []string{}
	}
	return json.Marshal(canonicalEntry{
		Attachments:   attachments,
		AuthorAccount: e.AuthorAccount,
		Body:          e.Body,
		Confidence:    e.Confidence,
		CreatedAt:     e.CreatedAt,
		DeviceSeq:     e.DeviceSeq,
		Domain:        e.Domain,
		EntryID:       e.EntryID,
		Markers:       m,
		Origin:        e.Origin,
		OriginDevice:  e.OriginDevice,
		SpaceID:       e.SpaceID,
		Title:         e.Title,
		Tombstone:     e.Tombstone,
		UpdatedAt:     e.UpdatedAt,
		Version:       e.Version,
	})
}

// SignEntry sets e.Signature = hex(Ed25519(devicePriv, SHA-256(canonical))).
func SignEntry(e *Entry, devicePriv ed25519.PrivateKey) error {
	b, err := CanonicalBytes(*e, nil)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	e.Signature = hex.EncodeToString(ed25519.Sign(devicePriv, sum[:]))
	return nil
}

// VerifyEntry checks an entry's signature against the origin device's pubkey (hex).
func VerifyEntry(e Entry, devicePubHex string) error {
	pub, err := hex.DecodeString(devicePubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid device pubkey")
	}
	sig, err := hex.DecodeString(e.Signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	b, err := CanonicalBytes(e, nil)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if !ed25519.Verify(ed25519.PublicKey(pub), sum[:], sig) {
		return errors.New("entry signature does not verify")
	}
	return nil
}

// PutParams are the caller-supplied fields for PutEntry.
type PutParams struct {
	EntryID    string // empty: create; set: new version of existing entry
	SpaceID    string
	Domain     string
	Title      string
	Body       string
	Markers    []string
	Confidence string // default "provisional"
	Origin     string // default "evidence"
	Provenance *Provenance
}

func validEnum(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// PutEntry creates an entry or a new version of an existing one: assigns
// entry_id/version/device_seq, canonically encodes and signs with the
// device key, and stores it (FTS index maintained by triggers).
func (s *Store) PutEntry(p PutParams) (Entry, error) {
	if s.signer == nil {
		return Entry{}, ErrNoSigner
	}
	if p.SpaceID == "" || p.Domain == "" || p.Title == "" {
		return Entry{}, errors.New("space, domain and title are required")
	}
	if p.Confidence == "" {
		p.Confidence = "provisional"
	}
	if p.Origin == "" {
		p.Origin = "evidence"
	}
	if !validEnum(p.Confidence, Confidences) {
		return Entry{}, fmt.Errorf("invalid confidence %q", p.Confidence)
	}
	if !validEnum(p.Origin, Origins) {
		return Entry{}, fmt.Errorf("invalid origin %q", p.Origin)
	}
	if _, err := s.GetSpace(p.SpaceID); err != nil {
		return Entry{}, fmt.Errorf("space %s: %w", p.SpaceID, err)
	}

	now := tsNow()
	e := Entry{
		EntryID:       p.EntryID,
		SpaceID:       p.SpaceID,
		Domain:        p.Domain,
		Title:         p.Title,
		Body:          p.Body,
		Markers:       p.Markers,
		Confidence:    p.Confidence,
		Origin:        p.Origin,
		AuthorAccount: s.signer.AccountID,
		AuthorDevice:  s.signer.DeviceID,
		CreatedAt:     now,
		UpdatedAt:     now,
		Version:       1,
		OriginDevice:  s.signer.DeviceID,
		Provenance:    p.Provenance,
	}
	if p.EntryID != "" {
		prev, err := s.GetEntry(p.EntryID)
		if err == nil {
			if prev.SpaceID != p.SpaceID {
				return Entry{}, errors.New("entry belongs to a different space")
			}
			e.CreatedAt = prev.CreatedAt
			e.Version = prev.Version + 1
			if e.UpdatedAt <= prev.UpdatedAt { // clock skew guard: keep LWW monotonic
				e.UpdatedAt = prev.UpdatedAt + "0"
			}
		} else if !errors.Is(err, ErrNotFound) {
			return Entry{}, err
		}
	} else {
		e.EntryID = uuid.NewString()
	}

	tx, err := s.db.Begin()
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback()
	seq, err := nextDeviceSeq(tx, e.SpaceID, e.OriginDevice)
	if err != nil {
		return Entry{}, err
	}
	e.DeviceSeq = seq
	if err := SignEntry(&e, s.signer.DevicePriv); err != nil {
		return Entry{}, err
	}
	if err := upsertEntry(tx, e); err != nil {
		return Entry{}, err
	}
	if err := tx.Commit(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// nextDeviceSeq allocates the per-(space, device) monotonic sequence from kv,
// so it survives LWW row replacement.
func nextDeviceSeq(tx *sql.Tx, spaceID, deviceID string) (int64, error) {
	k := "seq:" + spaceID + ":" + deviceID
	var cur int64
	err := tx.QueryRow(`SELECT CAST(v AS INTEGER) FROM kv WHERE k=?`, k).Scan(&cur)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	cur++
	if _, err := tx.Exec(`INSERT INTO kv(k,v) VALUES(?,?)
		ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, fmt.Sprint(cur)); err != nil {
		return 0, err
	}
	return cur, nil
}

func markersJSON(m []string) string {
	if m == nil {
		m = []string{}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func provenanceJSON(p *Provenance) any {
	if p == nil {
		return nil
	}
	b, _ := json.Marshal(p)
	return string(b)
}

func upsertEntry(tx *sql.Tx, e Entry) error {
	_, err := tx.Exec(`INSERT INTO entries(
		entry_id,space_id,domain,title,body,markers,confidence,origin,
		author_account,author_device,created_at,updated_at,version,device_seq,
		origin_device,signature,provenance,tombstone)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(entry_id) DO UPDATE SET
		space_id=excluded.space_id, domain=excluded.domain, title=excluded.title,
		body=excluded.body, markers=excluded.markers, confidence=excluded.confidence,
		origin=excluded.origin, author_account=excluded.author_account,
		author_device=excluded.author_device, created_at=excluded.created_at,
		updated_at=excluded.updated_at, version=excluded.version,
		device_seq=excluded.device_seq, origin_device=excluded.origin_device,
		signature=excluded.signature, provenance=excluded.provenance,
		tombstone=excluded.tombstone`,
		e.EntryID, e.SpaceID, e.Domain, e.Title, e.Body, markersJSON(e.Markers),
		e.Confidence, e.Origin, e.AuthorAccount, e.AuthorDevice, e.CreatedAt,
		e.UpdatedAt, e.Version, e.DeviceSeq, e.OriginDevice, e.Signature,
		provenanceJSON(e.Provenance), boolInt(e.Tombstone))
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const entryCols = `entry_id,space_id,domain,title,body,markers,confidence,origin,
	author_account,author_device,created_at,updated_at,version,device_seq,
	origin_device,signature,provenance,tombstone`

func scanEntry(sc interface{ Scan(...any) error }) (Entry, error) {
	var e Entry
	var markers string
	var prov sql.NullString
	var tomb int
	err := sc.Scan(&e.EntryID, &e.SpaceID, &e.Domain, &e.Title, &e.Body, &markers,
		&e.Confidence, &e.Origin, &e.AuthorAccount, &e.AuthorDevice,
		&e.CreatedAt, &e.UpdatedAt, &e.Version, &e.DeviceSeq,
		&e.OriginDevice, &e.Signature, &prov, &tomb)
	if err != nil {
		return Entry{}, err
	}
	if markers != "" {
		if err := json.Unmarshal([]byte(markers), &e.Markers); err != nil {
			return Entry{}, fmt.Errorf("entry %s markers: %w", e.EntryID, err)
		}
	}
	if len(e.Markers) == 0 {
		e.Markers = nil
	}
	if prov.Valid && prov.String != "" {
		var p Provenance
		if err := json.Unmarshal([]byte(prov.String), &p); err != nil {
			return Entry{}, fmt.Errorf("entry %s provenance: %w", e.EntryID, err)
		}
		e.Provenance = &p
	}
	e.Tombstone = tomb != 0
	return e, nil
}

// GetEntry returns an entry by id (including tombstoned ones).
func (s *Store) GetEntry(entryID string) (Entry, error) {
	row := s.db.QueryRow(`SELECT `+entryCols+` FROM entries WHERE entry_id=?`, entryID)
	e, err := scanEntry(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	return e, err
}

func (s *Store) queryEntries(q string, args ...any) ([]Entry, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetDomain returns live entries in a domain; spaceIDs nil means all spaces.
func (s *Store) GetDomain(domain string, spaceIDs []string) ([]Entry, error) {
	q := `SELECT ` + entryCols + ` FROM entries WHERE domain=? AND tombstone=0`
	args := []any{domain}
	if len(spaceIDs) > 0 {
		q += ` AND space_id IN (` + placeholders(len(spaceIDs)) + `)`
		for _, id := range spaceIDs {
			args = append(args, id)
		}
	}
	q += ` ORDER BY updated_at DESC`
	return s.queryEntries(q, args...)
}

// ListEntries returns all live entries of a space, ordered by domain then title.
func (s *Store) ListEntries(spaceID string) ([]Entry, error) {
	return s.queryEntries(`SELECT `+entryCols+` FROM entries
		WHERE space_id=? AND tombstone=0 ORDER BY domain, title`, spaceID)
}

// DeleteEntry writes a tombstone version of the entry (deletes propagate).
func (s *Store) DeleteEntry(entryID string) error {
	if s.signer == nil {
		return ErrNoSigner
	}
	e, err := s.GetEntry(entryID)
	if err != nil {
		return err
	}
	if e.Tombstone {
		return nil
	}
	now := tsNow()
	if now <= e.UpdatedAt {
		now = e.UpdatedAt + "0"
	}
	e.UpdatedAt = now
	e.Version++
	e.Tombstone = true
	e.AuthorAccount = s.signer.AccountID
	e.AuthorDevice = s.signer.DeviceID
	e.OriginDevice = s.signer.DeviceID
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seq, err := nextDeviceSeq(tx, e.SpaceID, e.OriginDevice)
	if err != nil {
		return err
	}
	e.DeviceSeq = seq
	if err := SignEntry(&e, s.signer.DevicePriv); err != nil {
		return err
	}
	if err := upsertEntry(tx, e); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplyRemote applies an incoming entry version under last-writer-wins:
// the incoming version wins iff (updated_at, author_account) is strictly
// greater than the local one, compared lexicographically. Returns whether
// it was applied. Signature verification is the sync layer's job.
func (s *Store) ApplyRemote(e Entry) (bool, error) {
	local, err := s.GetEntry(e.EntryID)
	switch {
	case errors.Is(err, ErrNotFound):
		// no local version: accept
	case err != nil:
		return false, err
	default:
		if e.UpdatedAt < local.UpdatedAt ||
			(e.UpdatedAt == local.UpdatedAt && e.AuthorAccount <= local.AuthorAccount) {
			return false, nil
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := upsertEntry(tx, e); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// CopyEntry copies an entry into another space with provenance
// (source_entry, source_space, copied_at). Always a copy, never a move.
// User-model layers (profile/, feedback/) refuse with ErrUserModel.
func (s *Store) CopyEntry(entryID, toSpaceID string) (Entry, error) {
	src, err := s.GetEntry(entryID)
	if err != nil {
		return Entry{}, err
	}
	if src.Tombstone {
		return Entry{}, fmt.Errorf("entry %s is deleted", entryID)
	}
	if userModelLayer(src.Domain) {
		return Entry{}, ErrUserModel
	}
	if src.SpaceID == toSpaceID {
		return Entry{}, errors.New("entry is already in that space")
	}
	return s.PutEntry(PutParams{
		SpaceID:    toSpaceID,
		Domain:     src.Domain,
		Title:      src.Title,
		Body:       src.Body,
		Markers:    src.Markers,
		Confidence: src.Confidence,
		Origin:     src.Origin,
		Provenance: &Provenance{
			SourceEntry: src.EntryID,
			SourceSpace: src.SpaceID,
			CopiedAt:    tsNow(),
		},
	})
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
