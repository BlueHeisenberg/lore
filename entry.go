package lore

import (
	"context"
	"strings"
	"time"

	"github.com/BlueHeisenberg/lore/internal/store"
)

// Confidence is how much weight an entry carries. The zero value means the
// store's default, Provisional.
type Confidence string

// The confidence vocabulary. It is closed: a value outside it is
// ErrInvalidArgument, not a free-form tag.
const (
	Experimental Confidence = "experimental"
	Provisional  Confidence = "provisional"
	Validated    Confidence = "validated"
	Hardened     Confidence = "hardened"
)

// Valid reports whether c is in the vocabulary. The zero value is not valid;
// it is a request for the default.
func (c Confidence) Valid() bool {
	switch c {
	case Experimental, Provisional, Validated, Hardened:
		return true
	}
	return false
}

// Origin is where an entry came from. The zero value means Evidence.
type Origin string

// The origin vocabulary. Closed, like Confidence.
const (
	Evidence   Origin = "evidence"
	Directive  Origin = "directive"
	Convention Origin = "convention"
	Constraint Origin = "constraint"
)

// Valid reports whether o is in the vocabulary. The zero value is not valid;
// it is a request for the default.
func (o Origin) Valid() bool {
	switch o {
	case Evidence, Directive, Convention, Constraint:
		return true
	}
	return false
}

// Timestamp is one of lore's timestamps: RFC3339 with nine fractional digits
// in UTC, so that lexicographic order is chronological order — which is what
// the last-writer-wins rule compares.
//
// It is a string and not a time.Time because it is not always a valid RFC3339
// instant. When two versions of an entry are written inside one clock tick,
// lore appends literal "0" characters to force the later string strictly
// greater than the earlier one. Time strips those and parses what is left.
type Timestamp string

// Time parses the timestamp, tolerating the same-tick "0" padding. The zero
// Timestamp is an error, not the zero time.
func (t Timestamp) Time() (time.Time, error) {
	s := string(t)
	// Timestamps are always UTC, so anything after the trailing "Z" is
	// same-tick padding.
	if i := strings.LastIndexByte(s, 'Z'); i >= 0 {
		s = s[:i+1]
	}
	return time.Parse(time.RFC3339Nano, s)
}

// Provenance records where a copied entry came from. CopyEntry sets it; it is
// nil on an entry that was authored rather than copied.
type Provenance struct {
	SourceEntry string
	SourceSpace string
	CopiedAt    Timestamp
}

// Entry is the unit of knowledge.
//
// Every Entry this package returns is complete: Body is the whole body, never
// an excerpt. Search returns whole entries with a Snippet alongside.
type Entry struct {
	ID      string
	SpaceID string
	Domain  string // layer/name, e.g. ops/deploy
	Title   string
	Body    string

	// Markers are free-form bracketed tags, e.g. "[IMPORTANT]". lore
	// normalises them on write (see NormalizeMarkers) but constrains them to
	// no vocabulary: treat the contents as arbitrary text.
	Markers    []string
	Confidence Confidence
	Origin     Origin

	// AuthorAccount is the hex account key of whoever wrote this version. The
	// device that wrote it is not reported: it is sync bookkeeping.
	AuthorAccount string

	CreatedAt Timestamp
	UpdatedAt Timestamp

	// Version counts versions of this entry, starting at 1.
	Version int64

	// Provenance is set on an entry created by CopyEntry, nil otherwise.
	Provenance *Provenance
}

// entryOf converts an internal entry, dropping the sync bookkeeping
// (AuthorDevice, DeviceSeq, OriginDevice, Signature) and the tombstone flag —
// a tombstone never reaches a caller of this package.
func entryOf(e store.Entry) Entry {
	out := Entry{
		ID:            e.EntryID,
		SpaceID:       e.SpaceID,
		Domain:        e.Domain,
		Title:         e.Title,
		Body:          e.Body,
		Markers:       e.Markers,
		Confidence:    Confidence(e.Confidence),
		Origin:        Origin(e.Origin),
		AuthorAccount: e.AuthorAccount,
		CreatedAt:     Timestamp(e.CreatedAt),
		UpdatedAt:     Timestamp(e.UpdatedAt),
		Version:       e.Version,
	}
	if e.Provenance != nil {
		out.Provenance = &Provenance{
			SourceEntry: e.Provenance.SourceEntry,
			SourceSpace: e.Provenance.SourceSpace,
			CopiedAt:    Timestamp(e.Provenance.CopiedAt),
		}
	}
	return out
}

func entriesOf(in []store.Entry) []Entry {
	if in == nil {
		return nil
	}
	out := make([]Entry, len(in))
	for i, e := range in {
		out[i] = entryOf(e)
	}
	return out
}

// PutParams are the caller-supplied fields of a write.
type PutParams struct {
	// ID empty creates an entry; ID set writes a new version of that entry,
	// which must already live in SpaceID or the write is ErrWrongSpace.
	ID         string
	SpaceID    string // required
	Domain     string // required, layer/name
	Title      string // required
	Body       string
	Markers    []string
	Confidence Confidence // zero: Provisional
	Origin     Origin     // zero: Evidence
}

// PutEntry creates an entry or a new version of one, signs it with this
// device's key and commits it. The returned Entry is what was stored.
//
// Markers are normalised on the way in (see NormalizeMarkers).
//
// Writing into a shared space that has a verified member list requires the
// writer or owner role: otherwise ErrNotWriter, and nothing is written.
func (s *Store) PutEntry(ctx context.Context, p PutParams) (Entry, error) {
	switch {
	case s.readOnly:
		return Entry{}, ErrReadOnly
	case p.SpaceID == "":
		return Entry{}, invalid("SpaceID is required")
	case p.Domain == "":
		return Entry{}, invalid("Domain is required")
	case p.Title == "":
		return Entry{}, invalid("Title is required")
	case p.Confidence != "" && !p.Confidence.Valid():
		return Entry{}, invalid("confidence %q", p.Confidence)
	case p.Origin != "" && !p.Origin.Valid():
		return Entry{}, invalid("origin %q", p.Origin)
	}
	var e store.Entry
	err := s.do(ctx, func() error {
		var err error
		e, err = s.st.PutEntry(store.PutParams{
			EntryID:    p.ID,
			SpaceID:    p.SpaceID,
			Domain:     p.Domain,
			Title:      p.Title,
			Body:       p.Body,
			Markers:    NormalizeMarkers(p.Markers),
			Confidence: string(p.Confidence),
			Origin:     string(p.Origin),
		})
		return err
	})
	if err != nil {
		return Entry{}, err
	}
	s.afterWrite(e.SpaceID)
	return entryOf(e), nil
}

// GetEntry returns the live entry with this id.
//
// A deleted entry is ErrNotFound. Entry ids are global to a store, so an id
// alone names an entry in any space; a caller that did not itself scope the
// id should use GetEntryIn.
func (s *Store) GetEntry(ctx context.Context, entryID string) (Entry, error) {
	return s.getEntry(ctx, "", entryID)
}

// GetEntryIn is GetEntry scoped to a space. An entry that exists but lives
// somewhere else is ErrWrongSpace and is not returned, so an id obtained
// inside one space cannot be used to read out of another.
func (s *Store) GetEntryIn(ctx context.Context, spaceID, entryID string) (Entry, error) {
	if spaceID == "" {
		return Entry{}, invalid("spaceID is required")
	}
	return s.getEntry(ctx, spaceID, entryID)
}

func (s *Store) getEntry(ctx context.Context, spaceID, entryID string) (Entry, error) {
	if entryID == "" {
		return Entry{}, invalid("entryID is required")
	}
	var e store.Entry
	err := s.do(ctx, func() error {
		var err error
		e, err = s.st.GetEntry(entryID)
		return err
	})
	if err != nil {
		return Entry{}, err
	}
	// The internal store returns tombstones because sync needs them. A reader
	// is not sync: a deleted entry is gone.
	if e.Tombstone {
		return Entry{}, ErrNotFound
	}
	if spaceID != "" && e.SpaceID != spaceID {
		return Entry{}, ErrWrongSpace
	}
	return entryOf(e), nil
}

// DeleteEntry writes a signed tombstone. The delete propagates to every
// synced device under the same last-writer-wins rule as any other write.
// There is no undo.
//
// It is space-scoped for the reason GetEntryIn is: an unknown id is
// ErrNotFound and an id belonging to another space is ErrWrongSpace, and
// neither deletes anything.
//
// Deleting an already-deleted entry is a no-op, not an error. deleted reports
// whether this call wrote the tombstone; when it is false nothing was
// written and the returned Entry is the tombstone that was already there.
// That distinction exists because "it is gone" and "you removed it" are
// different things to tell a person.
func (s *Store) DeleteEntry(ctx context.Context, spaceID, entryID string) (e Entry, deleted bool, err error) {
	switch {
	case s.readOnly:
		return Entry{}, false, ErrReadOnly
	case spaceID == "":
		return Entry{}, false, invalid("spaceID is required")
	case entryID == "":
		return Entry{}, false, invalid("entryID is required")
	}
	var raw store.Entry
	var before int64
	err = s.do(ctx, func() error {
		prev, err := s.st.GetEntry(entryID)
		if err != nil {
			return err
		}
		before = prev.Version
		raw, err = s.st.DeleteEntry(spaceID, entryID)
		return err
	})
	if err != nil {
		return Entry{}, false, err
	}
	// A no-op delete returns the existing tombstone untouched, so an
	// unchanged version is exactly "nothing was written".
	deleted = raw.Version != before
	if deleted {
		s.afterWrite(spaceID)
	}
	return entryOf(raw), deleted, nil
}

// ListEntries returns the live entries of a space, ordered by domain then
// title. It loads every body; use CountEntries to count.
func (s *Store) ListEntries(ctx context.Context, spaceID string) ([]Entry, error) {
	if spaceID == "" {
		return nil, invalid("spaceID is required")
	}
	var es []store.Entry
	err := s.do(ctx, func() error {
		var err error
		es, err = s.st.ListEntries(spaceID)
		return err
	})
	return entriesOf(es), err
}

// CountEntries returns how many live entries a space holds, without reading
// a single body.
func (s *Store) CountEntries(ctx context.Context, spaceID string) (int, error) {
	if spaceID == "" {
		return 0, invalid("spaceID is required")
	}
	var n int
	err := s.do(ctx, func() error {
		var err error
		n, err = s.st.CountEntries(spaceID)
		return err
	})
	return n, err
}

// GetDomain returns the live entries in a domain, newest first. spaceIDs nil
// means every space this store holds.
func (s *Store) GetDomain(ctx context.Context, domain string, spaceIDs []string) ([]Entry, error) {
	if domain == "" {
		return nil, invalid("domain is required")
	}
	var es []store.Entry
	err := s.do(ctx, func() error {
		var err error
		es, err = s.st.GetDomain(domain, spaceIDs)
		return err
	})
	return entriesOf(es), err
}

// CopyEntry copies an entry into another space, recording provenance. It is
// always a copy and never a move: the source stays where it is.
//
// Entries in the user-model layers — domains beginning profile/ or feedback/
// — never leave the personal space and refuse with ErrUserModel on every
// path.
func (s *Store) CopyEntry(ctx context.Context, entryID, toSpaceID string) (Entry, error) {
	switch {
	case s.readOnly:
		return Entry{}, ErrReadOnly
	case entryID == "":
		return Entry{}, invalid("entryID is required")
	case toSpaceID == "":
		return Entry{}, invalid("toSpaceID is required")
	}
	// Read the source first so the refusals are typed: the internal copy
	// reports "deleted" and "already in that space" as prose.
	src, err := s.GetEntry(ctx, entryID)
	if err != nil {
		return Entry{}, err
	}
	if src.SpaceID == toSpaceID {
		return Entry{}, invalid("entry %s is already in space %s", entryID, toSpaceID)
	}
	var e store.Entry
	err = s.do(ctx, func() error {
		var err error
		e, err = s.st.CopyEntry(entryID, toSpaceID)
		return err
	})
	if err != nil {
		return Entry{}, err
	}
	s.afterWrite(toSpaceID)
	return entryOf(e), nil
}

// NormalizeMarkers applies lore's marker normalisation, which every write
// goes through: trim, drop empties, and upper-case and bracket-wrap anything
// not already bracketed, so "context" becomes "[CONTEXT]". A marker that
// already starts with "[" is stored verbatim.
//
// Exported so a caller can predict what a write will store, rather than
// mirroring the rule by hand and drifting from it.
func NormalizeMarkers(in []string) []string {
	var out []string
	for _, m := range in {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if !strings.HasPrefix(m, "[") {
			m = "[" + strings.ToUpper(m) + "]"
		}
		out = append(out, m)
	}
	return out
}
