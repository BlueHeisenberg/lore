package store

import (
	"encoding/json"
	"strings"
)

// SearchOpts filter a full-text search.
type SearchOpts struct {
	Spaces     []string // space_ids; empty = all
	Domain     string
	Marker     string // e.g. "IMPORTANT" or "[IMPORTANT]"
	Confidence string
	Limit      int // default 8
}

// SearchResult is an entry plus a highlighted body snippet.
type SearchResult struct {
	Entry
	Snippet string
}

// ftsQuery turns free text into an FTS5 query: each whitespace token becomes
// a quoted term (implicit AND), so user input can't inject FTS syntax.
func ftsQuery(q string) string {
	fields := strings.Fields(q)
	terms := make([]string, 0, len(fields))
	for _, f := range fields {
		terms = append(terms, `"`+strings.ReplaceAll(f, `"`, `""`)+`"`)
	}
	return strings.Join(terms, " ")
}

// Search runs an FTS5 match over title/body/domain with optional filters,
// excluding tombstones, best matches first.
func (s *Store) Search(query string, o SearchOpts) ([]SearchResult, error) {
	fq := ftsQuery(query)
	if fq == "" {
		return nil, nil
	}
	if o.Limit <= 0 {
		o.Limit = 8
	}
	cols := make([]string, 0, 18)
	for _, c := range strings.Split(entryCols, ",") {
		cols = append(cols, "entries."+strings.TrimSpace(c))
	}
	q := `SELECT ` + strings.Join(cols, ",") + `, snippet(entry_fts, 1, '[', ']', '…', 12)
		FROM entry_fts JOIN entries ON entries.rowid = entry_fts.rowid
		WHERE entry_fts MATCH ? AND entries.tombstone=0`
	args := []any{fq}
	if len(o.Spaces) > 0 {
		q += ` AND entries.space_id IN (` + placeholders(len(o.Spaces)) + `)`
		for _, id := range o.Spaces {
			args = append(args, id)
		}
	}
	if o.Domain != "" {
		q += ` AND entries.domain = ?`
		args = append(args, o.Domain)
	}
	if o.Confidence != "" {
		q += ` AND entries.confidence = ?`
		args = append(args, o.Confidence)
	}
	if o.Marker != "" {
		m := strings.Trim(o.Marker, "[]")
		// markers is a JSON array of "[NAME]" strings.
		q += ` AND entries.markers LIKE ? ESCAPE '\'`
		args = append(args, `%"[`+strings.ToUpper(m)+`]"%`)
	}
	q += ` ORDER BY rank LIMIT ?`
	args = append(args, o.Limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchResult
	for rows.Next() {
		var r SearchResult
		var markers string
		var prov, snippet *string
		var tomb int
		err := rows.Scan(&r.EntryID, &r.SpaceID, &r.Domain, &r.Title, &r.Body, &markers,
			&r.Confidence, &r.Origin, &r.AuthorAccount, &r.AuthorDevice,
			&r.CreatedAt, &r.UpdatedAt, &r.Version, &r.DeviceSeq,
			&r.OriginDevice, &r.Signature, &prov, &tomb, &snippet)
		if err != nil {
			return nil, err
		}
		if markers != "" {
			_ = json.Unmarshal([]byte(markers), &r.Markers)
		}
		if len(r.Markers) == 0 {
			r.Markers = nil
		}
		if prov != nil && *prov != "" {
			var p Provenance
			if err := json.Unmarshal([]byte(*prov), &p); err == nil {
				r.Provenance = &p
			}
		}
		r.Tombstone = tomb != 0
		if snippet != nil {
			r.Snippet = *snippet
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
