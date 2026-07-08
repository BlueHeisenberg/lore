// Package distill mirrors the personal space to/from an aura-distill
// directory (~/.claude/distill): import parses layer/name.md files into
// entries, render materializes entries back to files and regenerates
// SPINE.md, watch imports external edits with a self-write loop-guard.
// See docs/IMPLEMENTATION.md and docs/DISTILL.md.
package distill

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/BlueHeisenberg/lore/internal/store"
)

// SpineFile is the derived index file: never imported, always regenerated.
const SpineFile = "SPINE.md"

var markerRe = regexp.MustCompile(`\[(CONTEXT|UPDATED|PROVISIONAL|IMPORTANT|NON-NEGOTIABLE|DIRECTIVE|CORRECTED|DEPRECATED)\]`)

// ScrapeMarkers extracts distill markers from a body, unique, in order of
// first appearance, brackets kept (e.g. "[CONTEXT]").
func ScrapeMarkers(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range markerRe.FindAllString(body, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

var confidenceRe = regexp.MustCompile(`(?m)^confidence:\s*(\w+)\s*$`)

// frontmatterConfidence pulls a valid confidence from YAML frontmatter if
// present; otherwise the import default "validated" (the file survived a
// distill retrospective already).
func frontmatterConfidence(body string) string {
	const def = "validated"
	rest, ok := strings.CutPrefix(body, "---\n")
	if !ok {
		return def
	}
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return def
	}
	m := confidenceRe.FindStringSubmatch(rest[:end])
	if m == nil {
		return def
	}
	for _, c := range store.Confidences {
		if m[1] == c {
			return c
		}
	}
	return def
}

// titleOf returns the first "# " heading, else the filename without extension.
func titleOf(body, filename string) string {
	for _, line := range strings.Split(body, "\n") {
		if h, ok := strings.CutPrefix(line, "# "); ok {
			return strings.TrimSpace(h)
		}
	}
	return strings.TrimSuffix(filepath.Base(filename), ".md")
}

// ImportResult summarizes an import run.
type ImportResult struct {
	Imported int // entries created or updated
	Skipped  int // unchanged files
}

// Import walks the distill dir's layer subdirectories (craft/ops/projects/
// profile/feedback plus any other dir) and imports every layer/name.md as
// one entry into spaceID: domain "layer/name", title from the first H1,
// markers scraped, confidence from frontmatter else "validated", origin
// "evidence". SPINE.md is skipped (it is derived, regenerated on render).
// Re-importing an unchanged file is a no-op; a changed file becomes a new
// version of the existing (space, domain) entry.
func Import(st *store.Store, spaceID, dir string) (ImportResult, error) {
	var res ImportResult
	layers, err := os.ReadDir(dir)
	if err != nil {
		return res, fmt.Errorf("distill dir: %w", err)
	}
	for _, layer := range layers {
		if !layer.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, layer.Name()))
		if err != nil {
			return res, err
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".md") || f.Name() == SpineFile {
				continue
			}
			path := filepath.Join(dir, layer.Name(), f.Name())
			imported, err := importFile(st, spaceID, dir, path)
			if err != nil {
				return res, fmt.Errorf("%s: %w", path, err)
			}
			if imported {
				res.Imported++
			} else {
				res.Skipped++
			}
		}
	}
	return res, nil
}

// importFile imports a single layer/name.md file; returns false if the
// entry already matches the file body (no new version written).
func importFile(st *store.Store, spaceID, dir, path string) (bool, error) {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false, err
	}
	rel = filepath.ToSlash(rel)
	if rel == SpineFile || !strings.HasSuffix(strings.ToLower(rel), ".md") {
		return false, nil
	}
	parts := strings.Split(rel, "/")
	if len(parts) != 2 { // only layer/name.md, v1
		return false, nil
	}
	domain := parts[0] + "/" + strings.TrimSuffix(parts[1], filepath.Ext(parts[1]))

	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	body := string(raw)

	var existingID string
	if prev, err := st.GetDomain(domain, []string{spaceID}); err != nil {
		return false, err
	} else if len(prev) > 0 {
		if prev[0].Body == body {
			return false, nil // unchanged
		}
		existingID = prev[0].EntryID
	}
	_, err = st.PutEntry(store.PutParams{
		EntryID:    existingID,
		SpaceID:    spaceID,
		Domain:     domain,
		Title:      titleOf(body, path),
		Body:       body,
		Markers:    ScrapeMarkers(body),
		Confidence: frontmatterConfidence(body),
		Origin:     "evidence",
	})
	return err == nil, err
}

// RenderRecord remembers what the renderer wrote (path -> content hash) so
// the watcher can skip self-writes.
type RenderRecord struct {
	mu     sync.Mutex
	hashes map[string]string
}

func newRenderRecord() *RenderRecord {
	return &RenderRecord{hashes: map[string]string{}}
}

func hashContent(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (r *RenderRecord) record(path string, content []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hashes[filepath.Clean(path)] = hashContent(content)
}

// IsSelfWrite reports whether content at path is byte-identical to what the
// renderer last wrote there.
func (r *RenderRecord) IsSelfWrite(path string, content []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hashes[filepath.Clean(path)] == hashContent(content)
}

// Render materializes spaceID's live entries into dir (one file per entry
// at <domain>.md, i.e. layer/name.md) and regenerates SPINE.md. Files whose
// content already matches are left untouched. Returns the RenderRecord for
// the watcher's loop-guard.
func Render(st *store.Store, spaceID, dir string) (*RenderRecord, error) {
	entries, err := st.ListEntries(spaceID)
	if err != nil {
		return nil, err
	}
	rec := newRenderRecord()
	for _, e := range entries {
		path := filepath.Join(dir, filepath.FromSlash(e.Domain)+".md")
		content := []byte(e.Body)
		rec.record(path, content)
		if cur, err := os.ReadFile(path); err == nil && string(cur) == e.Body {
			continue // identical, don't touch mtime
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return nil, err
		}
	}
	spine := renderSpine(entries)
	spinePath := filepath.Join(dir, SpineFile)
	rec.record(spinePath, spine)
	if cur, err := os.ReadFile(spinePath); err != nil || string(cur) != string(spine) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(spinePath, spine, 0o600); err != nil {
			return nil, err
		}
	}
	return rec, nil
}

// firstBodyLine returns the first non-empty, non-heading, non-frontmatter
// line of a body, for SPINE descriptions.
func firstBodyLine(body string) string {
	lines := strings.Split(body, "\n")
	i := 0
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == "---" { // skip frontmatter
		for i++; i < len(lines) && strings.TrimSpace(lines[i]) != "---"; i++ {
		}
		i++
	}
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		return l
	}
	return ""
}

const spineMaxLines = 80

// renderSpine builds SPINE.md: grouped by layer, one pointer line per entry
// ("- [Title](layer/name.md) — first body line"), capped at 80 lines.
func renderSpine(entries []store.Entry) []byte {
	byLayer := map[string][]store.Entry{}
	var layers []string
	for _, e := range entries {
		layer, _, ok := strings.Cut(e.Domain, "/")
		if !ok {
			layer = "misc"
		}
		if _, seen := byLayer[layer]; !seen {
			layers = append(layers, layer)
		}
		byLayer[layer] = append(byLayer[layer], e)
	}
	sort.Strings(layers)

	lines := []string{"# SPINE", ""}
	for _, layer := range layers {
		block := []string{"## " + layer, ""}
		for _, e := range byLayer[layer] {
			line := fmt.Sprintf("- [%s](%s.md)", e.Title, e.Domain)
			if desc := firstBodyLine(e.Body); desc != "" {
				line += " — " + desc
			}
			block = append(block, line)
		}
		block = append(block, "")
		if len(lines)+len(block) > spineMaxLines {
			remaining := spineMaxLines - len(lines)
			if remaining > 2 { // room for header + at least one pointer
				lines = append(lines, block[:remaining]...)
			}
			break
		}
		lines = append(lines, block...)
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// Watcher imports external edits to the distill dir back into the store.
type Watcher struct {
	fs       *fsnotify.Watcher
	done     chan struct{}
	wg       sync.WaitGroup
	Debounce time.Duration
}

// Watch starts watching dir (and its layer subdirectories): file events are
// debounced (2s default), SPINE.md and renderer self-writes (per rec) are
// skipped, everything else is re-imported into spaceID as new entry
// versions. Close the returned Watcher to stop. rec may be nil.
func Watch(st *store.Store, spaceID, dir string, rec *RenderRecord, debounce time.Duration) (*Watcher, error) {
	if debounce <= 0 {
		debounce = 2 * time.Second
	}
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fw.Add(dir); err != nil {
		fw.Close()
		return nil, err
	}
	subs, err := os.ReadDir(dir)
	if err != nil {
		fw.Close()
		return nil, err
	}
	for _, sd := range subs {
		if sd.IsDir() {
			if err := fw.Add(filepath.Join(dir, sd.Name())); err != nil {
				fw.Close()
				return nil, err
			}
		}
	}

	w := &Watcher{fs: fw, done: make(chan struct{}), Debounce: debounce}
	w.wg.Add(1)
	go w.run(st, spaceID, dir, rec)
	return w, nil
}

func (w *Watcher) run(st *store.Store, spaceID, dir string, rec *RenderRecord) {
	defer w.wg.Done()
	pending := map[string]struct{}{}
	var timer *time.Timer
	var fire <-chan time.Time
	flush := func() {
		for path := range pending {
			delete(pending, path)
			content, err := os.ReadFile(path)
			if err != nil {
				continue // deleted or unreadable; v1 ignores
			}
			if rec != nil && rec.IsSelfWrite(path, content) {
				continue // loop-guard: our own render output
			}
			_, _ = importFile(st, spaceID, dir, path)
		}
	}
	for {
		select {
		case <-w.done:
			if timer != nil {
				timer.Stop()
			}
			return
		case ev, ok := <-w.fs.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
				continue
			}
			if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
				_ = w.fs.Add(ev.Name) // new layer directory
				continue
			}
			if filepath.Base(ev.Name) == SpineFile || !strings.HasSuffix(strings.ToLower(ev.Name), ".md") {
				continue
			}
			pending[ev.Name] = struct{}{}
			if timer == nil {
				timer = time.NewTimer(w.Debounce)
				fire = timer.C
			} else {
				timer.Reset(w.Debounce)
			}
		case <-fire:
			flush()
		case _, ok := <-w.fs.Errors:
			if !ok {
				return
			}
		}
	}
}

// Close stops the watcher and waits for the worker to exit.
func (w *Watcher) Close() error {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	err := w.fs.Close()
	w.wg.Wait()
	return err
}
