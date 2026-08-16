package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/BlueHeisenberg/lore/internal/store"
)

func init() {
	register("delete", "delete an entry (signed tombstone, propagates)", cmdDelete)
}

const deleteUsage = "usage: lore delete entry <id> --space <space> [--yes]"

// cmdDelete tombstones one entry. --space is required, not a convenience:
// entry ids are global, so an id alone would let a caller delete out of a
// space it never named. The entry is printed for review before the prompt,
// same shape as `lore share entry`.
func cmdDelete(args []string) error {
	if len(args) == 0 || args[0] != "entry" {
		return errors.New(deleteUsage)
	}
	fs := flag.NewFlagSet("delete entry", flag.ContinueOnError)
	spaceArg := fs.String("space", "", "space the entry lives in, name or id (required)")
	yes := fs.Bool("yes", false, "skip the confirmation prompt (automation)")
	pos, err := parseArgs(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 || *spaceArg == "" {
		return errors.New(deleteUsage)
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
	e, err := st.GetEntry(pos[0])
	if err != nil {
		return fmt.Errorf("entry %s: %w", pos[0], err)
	}
	if e.SpaceID != sp.SpaceID {
		return fmt.Errorf("entry %s: %w %q — nothing deleted", e.EntryID, store.ErrWrongSpace, sp.Name)
	}
	if e.Tombstone {
		fmt.Printf("already deleted: %s (tombstone v%d in %q) — nothing to do\n", e.EntryID, e.Version, sp.Name)
		return nil
	}

	names := spaceNames(st)
	fmt.Printf("DELETE — this entry would be removed from space %q (signed tombstone; it propagates to every device):\n\n", sp.Name)
	printEntry(os.Stdout, e, names[e.SpaceID])
	fmt.Println()
	if !*yes {
		if !promptYes(fmt.Sprintf("delete this entry from %q? [y/N] ", sp.Name)) {
			fmt.Println("nothing deleted")
			return nil
		}
	}
	dead, err := st.DeleteEntry(sp.SpaceID, e.EntryID)
	if err != nil {
		return err
	}
	fmt.Printf("ok: deleted %s from %q (tombstone v%d; gone from search and get)\n",
		dead.EntryID, sp.Name, dead.Version)
	return nil
}
