// Command lore is the lore CLI: local-first knowledge store.
// Phase 1 surface: init, put, get, search, spaces, status, distill import|render.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BlueHeisenberg/lore"
	"github.com/BlueHeisenberg/lore/internal/distill"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Errors from the public lore package already say "lore: "; the CLI
		// prefix is for everything else.
		fmt.Fprintln(os.Stderr, "lore:", strings.TrimPrefix(err.Error(), "lore: "))
		os.Exit(1)
	}
}

// command registry: each command lives in its own file and self-registers
// via register() from an init(), so adding commands never edits shared files.
type command struct {
	fn   func([]string) error
	desc string
}

var commands = map[string]command{}
var commandOrder []string

func register(name, desc string, fn func([]string) error) {
	commands[name] = command{fn: fn, desc: desc}
	commandOrder = append(commandOrder, name)
}

func init() {
	register("init", "create account, device and personal space", cmdInit)
	register("put", "create or update an entry", cmdPut)
	register("get", "print an entry by id, or all entries in a domain", cmdGet)
	register("search", "full-text search with filters", cmdSearch)
	register("spaces", "list spaces", cmdSpaces)
	register("status", "identity and store summary", cmdStatus)
	register("mirror", "import|render the markdown mirror of the personal space", cmdMirror)
}

func usage() error {
	fmt.Fprintln(os.Stderr, "usage: lore <command> [flags]")
	fmt.Fprintln(os.Stderr, "\ncommands:")
	names := append([]string(nil), commandOrder...)
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "  %-9s %s\n", name, commands[name].desc)
	}
	return errors.New("no command")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	cmd, rest := args[0], args[1:]
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		usage()
		return nil
	}
	if c, ok := commands[cmd]; ok {
		return c.fn(rest)
	}
	return fmt.Errorf("unknown command %q (try `lore help`)", cmd)
}

// parseArgs parses a flag set but accepts flags anywhere on the line
// (stdlib flag stops at the first positional argument; humans and agents
// write `lore search query --marker X`). Returns the positional arguments.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// loreHome returns LORE_HOME or ~/.lore.
func loreHome() (string, error) {
	if h := os.Getenv("LORE_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".lore"), nil
}

// config is LORE_HOME/config.json.
type config struct {
	MirrorDir string `json:"mirror_dir"`
}

// loadConfig reads LORE_HOME/config.json. The distill mirror is strictly
// opt-in: an empty mirror_dir means the adapter is off. Nothing in lore may
// default to the real ~/.claude/distill — pointing lore at a live directory
// it doesn't own is an explicit user decision (set mirror_dir in config.json
// or pass --dir to `lore distill`).
func loadConfig(loreHome string) config {
	var cfg config
	b, err := os.ReadFile(filepath.Join(loreHome, "config.json"))
	if err == nil {
		var c config
		if json.Unmarshal(b, &c) == nil && c.MirrorDir != "" {
			cfg.MirrorDir = c.MirrorDir
		}
	}
	return cfg
}

// openStore loads keys and opens the DB with a signer.
func openStore(home string) (*store.Store, *keys.Account, *keys.Device, error) {
	account, err := keys.LoadAccount(home)
	if err != nil {
		return nil, nil, nil, err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := device.Cert.VerifyForAccount(account.AccountID()); err != nil {
		return nil, nil, nil, err
	}
	priv, err := device.PrivateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := store.Open(filepath.Join(home, "lore.db"), &store.Signer{
		AccountID:  account.AccountID(),
		DeviceID:   device.DeviceID(),
		DevicePriv: priv,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return st, account, device, nil
}

// cmdInit is a wrapper over lore.Init. The confirmation now happens after the
// home exists, not before: the public Init mints the recovery code as part of
// creating the account, and the code protects nothing until a signup or a
// backup wraps something under it — so a mistyped confirmation costs a `lore
// recovery new`, not the account.
func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	name := fs.String("name", "", "device name (default: hostname)")
	yes := fs.Bool("yes-i-saved-it", false, "skip the recovery-code confirmation prompt (automation)")
	noPath := fs.Bool("no-path", false, "skip adding lore's directory to your PATH")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	id, err := lore.Init(home, *name)
	if err != nil {
		return err
	}
	fmt.Printf("account  %s\n", id.AccountID)
	fmt.Printf("device   %s (%s)\n", id.DeviceID, id.DeviceName)
	fmt.Printf("space    personal %s\n", id.PersonalSpaceID)
	fmt.Printf("\nrecovery code — shown once, store it in a password manager:\n\n  %s\n\n", id.RecoveryCode)
	if !*yes {
		fmt.Print("re-type the recovery code to confirm you saved it: ")
		line, rerr := bufio.NewReader(os.Stdin).ReadString('\n')
		if (rerr != nil && line == "") ||
			keys.NormalizeRecoveryCode(line) != keys.NormalizeRecoveryCode(id.RecoveryCode) {
			return fmt.Errorf("recovery code not confirmed — %s IS initialized; "+
				"run `lore recovery new` to mint another code and confirm that one", home)
		}
	}
	if !*noPath {
		// A store nobody can invoke is half an install — but the store is the
		// half that matters, so a PATH failure warns and init still succeeds.
		if err := ensureOnPath(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not add lore to your PATH: %v\n", err)
		}
	}
	fmt.Printf("ok: initialized %s\n", home)
	return nil
}

// resolveSpace maps a --space value (name or id, default personal) to a Space.
func resolveSpace(st *store.Store, arg string) (store.Space, error) {
	if arg == "" || arg == "personal" {
		return st.PersonalSpace()
	}
	if sp, err := st.GetSpace(arg); err == nil {
		return sp, nil
	}
	return st.SpaceByName(arg)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if !strings.HasPrefix(p, "[") {
				p = "[" + strings.ToUpper(p) + "]"
			}
			out = append(out, p)
		}
	}
	return out
}

func cmdPut(args []string) error {
	fs := flag.NewFlagSet("put", flag.ContinueOnError)
	domain := fs.String("domain", "", "entry domain, e.g. ops/deploy (required)")
	title := fs.String("title", "", "entry title (required)")
	spaceArg := fs.String("space", "", "space name or id (default: personal)")
	markers := fs.String("markers", "", "comma-separated markers, e.g. CONTEXT,IMPORTANT")
	confidence := fs.String("confidence", "", "experimental|provisional|validated|hardened (default provisional)")
	origin := fs.String("origin", "", "evidence|directive|convention|constraint (default evidence)")
	bodyFile := fs.String("body-file", "", "read body from file, or - for stdin")
	entryID := fs.String("entry", "", "existing entry id to update")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if *domain == "" || *title == "" {
		return errors.New("put: --domain and --title are required")
	}
	var body string
	switch {
	case *bodyFile == "-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		body = string(b)
	case *bodyFile != "":
		b, err := os.ReadFile(*bodyFile)
		if err != nil {
			return err
		}
		body = string(b)
	case len(pos) == 1 && pos[0] == "-":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		body = string(b)
	case len(pos) > 0:
		body = strings.Join(pos, " ")
	}

	home, err := loreHome()
	if err != nil {
		return err
	}
	st, _, _, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()
	sp, err := resolveSpace(st, *spaceArg)
	if err != nil {
		return fmt.Errorf("space %q: %w", *spaceArg, err)
	}
	e, err := st.PutEntry(store.PutParams{
		EntryID:    *entryID,
		SpaceID:    sp.SpaceID,
		Domain:     *domain,
		Title:      *title,
		Body:       body,
		Markers:    splitCSV(*markers),
		Confidence: *confidence,
		Origin:     *origin,
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s v%d %s %s (%s)\n", e.EntryID, e.Version, sp.Name, e.Domain, e.Confidence)
	return nil
}

func printEntry(w io.Writer, e store.Entry, spaceName string) {
	fmt.Fprintf(w, "id         %s (v%d)\n", e.EntryID, e.Version)
	fmt.Fprintf(w, "space      %s\n", spaceName)
	fmt.Fprintf(w, "domain     %s\n", e.Domain)
	fmt.Fprintf(w, "title      %s\n", e.Title)
	fmt.Fprintf(w, "confidence %s   origin %s\n", e.Confidence, e.Origin)
	if len(e.Markers) > 0 {
		fmt.Fprintf(w, "markers    %s\n", strings.Join(e.Markers, " "))
	}
	if e.Provenance != nil {
		fmt.Fprintf(w, "copied     from %s in space %s at %s\n",
			e.Provenance.SourceEntry, e.Provenance.SourceSpace, e.Provenance.CopiedAt)
	}
	if e.Tombstone {
		fmt.Fprintln(w, "deleted    true")
	}
	fmt.Fprintf(w, "updated    %s by %s\n", e.UpdatedAt, short(e.AuthorAccount))
	if e.Body != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimRight(e.Body, "\n"))
	}
}

func short(hexID string) string {
	if len(hexID) > 12 {
		return hexID[:12]
	}
	return hexID
}

func spaceNames(st *store.Store) map[string]string {
	names := map[string]string{}
	if sps, err := st.ListSpaces(); err == nil {
		for _, sp := range sps {
			names[sp.SpaceID] = sp.Name
		}
	}
	return names
}

func cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore get <entry-id|domain>")
	}
	arg := pos[0]
	home, err := loreHome()
	if err != nil {
		return err
	}
	st, _, _, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()
	names := spaceNames(st)

	if e, err := st.GetEntry(arg); err == nil {
		// GetEntry deliberately returns tombstones (sync needs them); a
		// deleted entry is gone as far as a reader is concerned — but say so,
		// rather than pretending the id never existed.
		if e.Tombstone {
			return fmt.Errorf("entry %s was deleted (tombstone v%d, %s)", e.EntryID, e.Version, e.UpdatedAt)
		}
		printEntry(os.Stdout, e, names[e.SpaceID])
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	es, err := st.GetDomain(arg, nil)
	if err != nil {
		return err
	}
	if len(es) == 0 {
		return fmt.Errorf("no entry or domain %q", arg)
	}
	for i, e := range es {
		if i > 0 {
			fmt.Println("\n---")
		}
		printEntry(os.Stdout, e, names[e.SpaceID])
	}
	return nil
}

// defaultScopeSpaces implements the default search scope: personal + the
// CWD's project space + pinned spaces. scope=all widens to every space.
func defaultScopeSpaces(st *store.Store) []string {
	var ids []string
	if p, err := st.PersonalSpace(); err == nil {
		ids = append(ids, p.SpaceID)
	}
	if cwd, err := os.Getwd(); err == nil {
		if ref, err := space.FindProjectRef(cwd); err == nil {
			if sp, err := st.SpaceByProjectRef(ref); err == nil {
				ids = append(ids, sp.SpaceID)
			}
		}
	}
	if sps, err := st.ListSpaces(); err == nil {
		for _, sp := range sps {
			if sp.Pinned && !contains(ids, sp.SpaceID) {
				ids = append(ids, sp.SpaceID)
			}
		}
	}
	return ids
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// cwdProjectSpace returns the project space for the CWD, if any.
func cwdProjectSpace(st *store.Store) (store.Space, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		return store.Space{}, false
	}
	ref, err := space.FindProjectRef(cwd)
	if err != nil {
		return store.Space{}, false
	}
	sp, err := st.SpaceByProjectRef(ref)
	if err != nil {
		return store.Space{}, false
	}
	return sp, true
}

// linkedScopeSpaces implements scope=linked: the CWD's project space plus
// its linked spaces. Links are retrieval hints only — a linked space id is
// included only when the space actually exists locally (which IS local
// membership: without membership it was never synced here).
func linkedScopeSpaces(st *store.Store) ([]string, error) {
	project, ok := cwdProjectSpace(st)
	if !ok {
		return nil, errors.New("the current directory has no project space (scope=linked); run `lore project init`")
	}
	ids := []string{project.SpaceID}
	links, err := st.Links(project.SpaceID)
	if err != nil {
		return nil, err
	}
	for _, id := range links {
		if contains(ids, id) {
			continue
		}
		if _, err := st.GetSpace(id); err == nil { // membership filter
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func cmdSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	spaceArg := fs.String("space", "", "restrict to one space (name or id)")
	scope := fs.String("scope", "default", "default|project|linked|all-mine|all (default: personal + CWD project + pinned)")
	domain := fs.String("domain", "", "filter by domain")
	marker := fs.String("marker", "", "filter by marker, e.g. IMPORTANT")
	confidence := fs.String("confidence", "", "filter by confidence")
	limit := fs.Int("limit", 8, "max results")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return errors.New("usage: lore search <query> [flags]")
	}
	query := strings.Join(pos, " ")

	home, err := loreHome()
	if err != nil {
		return err
	}
	st, _, _, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()

	var spaces []string
	switch {
	case *spaceArg != "":
		sp, err := resolveSpace(st, *spaceArg)
		if err != nil {
			return fmt.Errorf("space %q: %w", *spaceArg, err)
		}
		spaces = []string{sp.SpaceID}
	case *scope == "all" || *scope == "all-mine":
		// no filter: locally-present spaces ARE this account's memberships
	case *scope == "project":
		sp, ok := cwdProjectSpace(st)
		if !ok {
			return errors.New("the current directory has no project space (scope=project); run `lore project init`")
		}
		spaces = []string{sp.SpaceID}
	case *scope == "linked":
		if spaces, err = linkedScopeSpaces(st); err != nil {
			return err
		}
	default:
		spaces = defaultScopeSpaces(st)
	}

	results, err := st.Search(query, store.SearchOpts{
		Spaces: spaces, Domain: *domain, Marker: *marker,
		Confidence: *confidence, Limit: *limit,
	})
	if err != nil {
		return err
	}
	if len(results) == 0 {
		fmt.Println("no results")
		return nil
	}
	names := spaceNames(st)
	for _, r := range results {
		markers := ""
		if len(r.Markers) > 0 {
			markers = " " + strings.Join(r.Markers, "")
		}
		fmt.Printf("%s  %-10s %-20s %s (%s)%s\n    %s\n",
			short(r.EntryID), names[r.SpaceID], r.Domain, r.Title, r.Confidence, markers,
			strings.ReplaceAll(r.Snippet, "\n", " "))
	}
	return nil
}

func cmdSpaces(args []string) error {
	fs := flag.NewFlagSet("spaces", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	st, _, _, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()
	sps, err := st.ListSpaces()
	if err != nil {
		return err
	}
	for _, sp := range sps {
		extra := ""
		if sp.ProjectRef != "" {
			extra = "  project:" + short(sp.ProjectRef)
		}
		if sp.Pinned {
			extra += "  pinned"
		}
		members := 1
		if sp.Kind == "shared" {
			if doc, ok, err := st.LatestMemberDoc(sp.SpaceID); err == nil && ok {
				members = len(doc.Members)
			}
		}
		entries, _ := st.ListEntries(sp.SpaceID)
		fmt.Printf("%-12s %-8s %s  %d entries  %d member(s)%s\n",
			sp.Name, sp.Kind, sp.SpaceID, len(entries), members, extra)
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	st, account, device, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()
	fmt.Printf("home     %s\n", home)
	fmt.Printf("account  %s\n", account.AccountID())
	fmt.Printf("device   %s (%s)\n", device.DeviceID(), device.Name)
	fmt.Printf("daemon   not running (phase 1: no daemon)\n")
	fmt.Printf("relay    not configured\n")
	sps, err := st.ListSpaces()
	if err != nil {
		return err
	}
	total := 0
	for _, sp := range sps {
		es, _ := st.ListEntries(sp.SpaceID)
		total += len(es)
	}
	fmt.Printf("spaces   %d (%d entries)\n", len(sps), total)
	fmt.Printf("mirror   %s\n", loadConfig(home).MirrorDir)
	return nil
}

// cmdMirror manages the markdown mirror of the personal space. `import
// --dir` also serves as the migration path from an aura-distill directory
// (same on-disk format).
func cmdMirror(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lore mirror import|render [--dir <dir>] [--dry-run]")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("mirror "+sub, flag.ContinueOnError)
	dir := fs.String("dir", "", "directory (default: config mirror_dir; point --dir at an aura-distill directory to migrate it)")
	dryRun := fs.Bool("dry-run", false, "import only: report what would happen per file, write nothing")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	if *dir == "" {
		*dir = loadConfig(home).MirrorDir
	}
	if *dir == "" {
		return errors.New("no mirror_dir configured (set it in config.json or pass --dir)")
	}
	st, _, _, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()
	personal, err := st.PersonalSpace()
	if err != nil {
		return err
	}
	switch sub {
	case "import":
		if *dryRun {
			plan, err := distill.ImportPlan(st, personal.SpaceID, *dir)
			if err != nil {
				return err
			}
			var counts = map[distill.PlanAction]int{}
			for _, p := range plan {
				counts[p.Action]++
				if p.Action != distill.PlanUnchanged {
					fmt.Printf("%-9s %s\n", p.Action, p.Domain)
				}
			}
			fmt.Printf("dry-run: %d add, %d overwrite, %d unchanged (from %s)\n",
				counts[distill.PlanAdd], counts[distill.PlanOverwrite], counts[distill.PlanUnchanged], *dir)
			if counts[distill.PlanOverwrite] > 0 {
				fmt.Println("overwrite = an entry for that domain already exists with different content;")
				fmt.Println("importing makes this file the new current version everywhere (old content is replaced).")
			}
			return nil
		}
		res, err := distill.Import(st, personal.SpaceID, *dir)
		if err != nil {
			return err
		}
		fmt.Printf("imported %d, unchanged %d (from %s)\n", res.Imported, res.Skipped, *dir)
		return nil
	case "render":
		if _, err := distill.Render(st, personal.SpaceID, *dir); err != nil {
			return err
		}
		fmt.Printf("rendered personal space to %s\n", *dir)
		return nil
	default:
		return fmt.Errorf("unknown mirror subcommand %q (import|render)", sub)
	}
}
