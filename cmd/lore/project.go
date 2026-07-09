package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

func init() {
	register("project", "init/link the project space for the CWD's git repo", cmdProject)
}

func cmdProject(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lore project init | lore project link <space>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "init":
		return cmdProjectInit(rest)
	case "link":
		return cmdProjectLink(rest)
	default:
		return fmt.Errorf("unknown project subcommand %q (init|link)", sub)
	}
}

// cwdProject resolves the CWD's git remote to (project_ref, repo name).
func cwdProject() (ref, name string, err error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	remote, err := space.RemoteOriginURL(cwd)
	if err != nil {
		return "", "", err
	}
	return space.ProjectRef(remote), space.RepoName(remote), nil
}

func cmdProjectInit(args []string) error {
	fs := flag.NewFlagSet("project init", flag.ContinueOnError)
	name := fs.String("name", "", "space name (default: repository base name)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	ref, repoName, err := cwdProject()
	if err != nil {
		return err
	}
	if *name == "" {
		*name = repoName
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	st, account, _, err := openStore(home)
	if err != nil {
		return err
	}
	defer st.Close()
	if sp, err := st.SpaceByProjectRef(ref); err == nil {
		fmt.Printf("project space %q already exists for this repo (%s)\n", sp.Name, sp.SpaceID)
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	sp, err := createSharedSpace(st, account, *name, ref)
	if err != nil {
		return err
	}
	fmt.Printf("ok: created project space %q %s for ref %s (you are owner)\n",
		sp.Name, sp.SpaceID, short(ref))
	fmt.Println("searches from this repo now include it; `lore space invite " + sp.Name + "` to share it")
	return nil
}

func cmdProjectLink(args []string) error {
	fs := flag.NewFlagSet("project link", flag.ContinueOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore project link <space>")
	}
	ref, _, err := cwdProject()
	if err != nil {
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
	project, err := st.SpaceByProjectRef(ref)
	if err != nil {
		return fmt.Errorf("no project space for this repo (run `lore project init` first): %w", err)
	}
	target, err := resolveSpace(st, pos[0])
	if err != nil {
		return fmt.Errorf("space %q: %w", pos[0], err)
	}
	if err := st.AddLink(project.SpaceID, target.SpaceID); err != nil {
		return err
	}
	fmt.Printf("ok: searches in %q (scope=linked) now also consult %q\n", project.Name, target.Name)
	fmt.Println("note: a link is a retrieval hint, never an access grant — readers only ever see spaces they are members of")
	return nil
}
