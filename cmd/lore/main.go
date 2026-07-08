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
	"strings"

	"github.com/BlueHeisenberg/lore/internal/distill"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lore:", err)
		os.Exit(1)
	}
}

func usage() error {
	fmt.Fprint(os.Stderr, `usage: lore <command> [flags]

commands:
  init      create account, device and personal space
  put       create or update an entry
  get       print an entry by id, or all entries in a domain
  search    full-text search with filters
  spaces    list spaces
  status    identity and store summary
  distill   import|render the distill mirror directory
`)
	return errors.New("no command")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest)
	case "put":
		return cmdPut(rest)
	case "get":
		return cmdGet(rest)
	case "search":
		return cmdSearch(rest)
	case "spaces":
		return cmdSpaces(rest)
	case "status":
		return cmdStatus(rest)
	case "distill":
		return cmdDistill(rest)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (try `lore help`)", cmd)
	}
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
	DistillDir string `json:"distill_dir"`
}

func defaultDistillDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "distill")
}

func loadConfig(loreHome string) config {
	cfg := config{DistillDir: defaultDistillDir()}
	b, err := os.ReadFile(filepath.Join(loreHome, "config.json"))
	if err == nil {
		var c config
		if json.Unmarshal(b, &c) == nil && c.DistillDir != "" {
			cfg.DistillDir = c.DistillDir
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

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	name := fs.String("name", "", "device name (default: hostname)")
	yes := fs.Bool("yes-i-saved-it", false, "skip the recovery-code confirmation prompt (automation)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(home, keys.AccountFile)); err == nil {
		return fmt.Errorf("already initialized at %s", home)
	}
	if *name == "" {
		if *name, err = os.Hostname(); err != nil || *name == "" {
			*name = "device"
		}
	}

	account, err := keys.GenerateAccount()
	if err != nil {
		return err
	}
	device, err := keys.GenerateDevice(*name, account)
	if err != nil {
		return err
	}
	code, err := keys.NewRecoveryCode()
	if err != nil {
		return err
	}

	fmt.Printf("account  %s\n", account.AccountID())
	fmt.Printf("device   %s (%s)\n", device.DeviceID(), device.Name)
	fmt.Printf("\nrecovery code — shown once, store it in a password manager:\n\n  %s\n\n", code)
	if !*yes {
		fmt.Print("re-type the recovery code to confirm you saved it: ")
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return errors.New("recovery code not confirmed (use --yes-i-saved-it to skip)")
		}
		if keys.NormalizeRecoveryCode(line) != keys.NormalizeRecoveryCode(code) {
			return errors.New("recovery code mismatch — nothing was created, run `lore init` again")
		}
	}

	if err := keys.SaveAccount(home, account); err != nil {
		return err
	}
	if err := keys.SaveDevice(home, device); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(home, "blobs"), 0o700); err != nil {
		return err
	}
	cfgPath := filepath.Join(home, "config.json")
	if _, err := os.Stat(cfgPath); errors.Is(err, os.ErrNotExist) {
		b, _ := json.MarshalIndent(config{DistillDir: defaultDistillDir()}, "", "  ")
		if err := os.WriteFile(cfgPath, append(b, '\n'), 0o600); err != nil {
			return err
		}
	}

	st, _, _, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()
	key, err := space.NewSpaceKey()
	if err != nil {
		return err
	}
	sp, err := st.CreateSpace("personal", "personal", "", key)
	if err != nil {
		return err
	}
	fmt.Printf("space    personal %s\nok: initialized %s\n", sp.SpaceID, home)
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

func cmdSearch(args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	spaceArg := fs.String("space", "", "restrict to one space (name or id)")
	scope := fs.String("scope", "default", "default|all (default: personal + CWD project + pinned)")
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
	case *scope == "all":
		// no filter
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
		entries, _ := st.ListEntries(sp.SpaceID)
		fmt.Printf("%-12s %-8s %s  %d entries%s\n", sp.Name, sp.Kind, sp.SpaceID, len(entries), extra)
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
	fmt.Printf("distill  %s\n", loadConfig(home).DistillDir)
	return nil
}

func cmdDistill(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lore distill import|render [--dir <distill-dir>]")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("distill "+sub, flag.ContinueOnError)
	dir := fs.String("dir", "", "distill directory (default: config distill_dir)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	if *dir == "" {
		*dir = loadConfig(home).DistillDir
	}
	if *dir == "" {
		return errors.New("no distill_dir configured (set it in config.json or pass --dir)")
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
		return fmt.Errorf("unknown distill subcommand %q (import|render)", sub)
	}
}
