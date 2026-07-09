package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BlueHeisenberg/lore/internal/store"
)

func init() {
	register("share", "copy an entry into another space, with review", cmdShare)
}

func cmdShare(args []string) error {
	if len(args) == 0 || args[0] != "entry" {
		return errors.New("usage: lore share entry <id> --to <space> [--yes]")
	}
	fs := flag.NewFlagSet("share entry", flag.ContinueOnError)
	to := fs.String("to", "", "destination space name or id (required)")
	yes := fs.Bool("yes", false, "skip the review prompt (automation)")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 || *to == "" {
		return errors.New("usage: lore share entry <id> --to <space> [--yes]")
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

	src, err := st.GetEntry(pos[0])
	if err != nil {
		return fmt.Errorf("entry %s: %w", pos[0], err)
	}
	target, err := resolveSpace(st, *to)
	if err != nil {
		return fmt.Errorf("space %q: %w", *to, err)
	}
	// Early user-model refusal so nobody is teased with a review of content
	// that can never leave. The store re-enforces this in CopyEntry.
	if layer, _, _ := strings.Cut(src.Domain, "/"); layer == "profile" || layer == "feedback" {
		return store.ErrUserModel
	}

	names := spaceNames(st)
	fmt.Printf("REVIEW — this exact content would be COPIED into space %q:\n\n", target.Name)
	printEntry(os.Stdout, src, names[src.SpaceID])
	fmt.Println()
	if !*yes {
		if !promptYes(fmt.Sprintf("copy this entry into %q? [y/N] ", target.Name)) {
			fmt.Println("nothing shared")
			return nil
		}
	}
	copied, err := st.CopyEntry(src.EntryID, target.SpaceID)
	if err != nil {
		return err
	}
	fmt.Printf("ok: copied as %s into %q (source %s stays in %q; provenance recorded)\n",
		copied.EntryID, target.Name, src.EntryID, names[src.SpaceID])
	return nil
}
