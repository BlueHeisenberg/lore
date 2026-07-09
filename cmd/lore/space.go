package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
)

func init() {
	register("space", "create/pin/invite shared topic spaces", cmdSpace)
}

func cmdSpace(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lore space create <name> | pin <space> [--off] | invite <space> [--role writer|reader]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdSpaceCreate(rest)
	case "pin":
		return cmdSpacePin(rest)
	case "invite":
		return cmdSpaceInvite(rest)
	default:
		return fmt.Errorf("unknown space subcommand %q (create|pin|invite)", sub)
	}
}

// createSharedSpace creates a shared space with a fresh space_key and signs
// member-doc v1: the creating account as sole owner (its wrapped space_key
// travels inside the doc, like every member's).
func createSharedSpace(st *store.Store, account *keys.Account, name, projectRef string) (store.Space, error) {
	key, err := space.NewSpaceKey()
	if err != nil {
		return store.Space{}, err
	}
	sp, err := st.CreateSpace("shared", name, projectRef, key)
	if err != nil {
		return store.Space{}, err
	}
	wrapped, err := space.WrapSpaceKey(key, account.EncPub)
	if err != nil {
		return store.Space{}, err
	}
	signPriv, err := account.SigningKey()
	if err != nil {
		return store.Space{}, err
	}
	doc, err := space.NewMemberDoc(sp.SpaceID, space.Member{
		AccountPub:      account.SignPub,
		EncPub:          account.EncPub,
		Role:            space.RoleOwner,
		WrappedSpaceKey: wrapped,
	}, signPriv)
	if err != nil {
		return store.Space{}, err
	}
	if err := st.AddMemberDoc(sp.SpaceID, doc); err != nil {
		return store.Space{}, err
	}
	return sp, nil
}

func cmdSpaceCreate(args []string) error {
	fs := flag.NewFlagSet("space create", flag.ContinueOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore space create <name>")
	}
	name := pos[0]
	if name == "personal" {
		return errors.New(`"personal" is reserved`)
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
	if _, err := st.SpaceByName(name); err == nil {
		return fmt.Errorf("a space named %q already exists", name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	sp, err := createSharedSpace(st, account, name, "")
	if err != nil {
		return err
	}
	fmt.Printf("ok: created topic space %q %s (you are owner)\n", sp.Name, sp.SpaceID)
	fmt.Println("tip: `lore space invite " + sp.Name + "` to share it; `lore space pin " + sp.Name + "` to add it to the default search scope")
	return nil
}

func cmdSpacePin(args []string) error {
	fs := flag.NewFlagSet("space pin", flag.ContinueOnError)
	off := fs.Bool("off", false, "unpin instead")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore space pin <space> [--off]")
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
	sp, err := resolveSpace(st, pos[0])
	if err != nil {
		return fmt.Errorf("space %q: %w", pos[0], err)
	}
	if err := st.SetPinned(sp.SpaceID, !*off); err != nil {
		return err
	}
	if *off {
		fmt.Printf("ok: unpinned %q\n", sp.Name)
	} else {
		fmt.Printf("ok: pinned %q — it now joins the default search scope\n", sp.Name)
	}
	return nil
}

// promptYes prints prompt and reads one line; returns true for y/yes.
func promptYes(prompt string) bool {
	fmt.Print(prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func cmdSpaceInvite(args []string) error {
	fs := flag.NewFlagSet("space invite", flag.ContinueOnError)
	role := fs.String("role", space.RoleWriter, "role granted to the invitee: writer|reader")
	yes := fs.Bool("yes", false, "skip the fingerprint confirmation prompt (automation)")
	lan := fs.Bool("lan", true, "listen on LAN interfaces")
	noMDNS := fs.Bool("no-mdns", false, "do not advertise via mDNS (joiner must pass --addr)")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore space invite <space> [--role writer|reader]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	st, _, _, err := openStore(home)
	if err != nil {
		return err
	}
	sp, err := resolveSpace(st, pos[0])
	st.Close() // the inviter opens its own handle
	if err != nil {
		return fmt.Errorf("space %q: %w", pos[0], err)
	}
	if sp.Kind == "personal" {
		return errors.New("the personal space cannot be shared (lore enroll adds your own devices)")
	}

	confirm := func(words, acct, name string) bool {
		fmt.Printf("\njoin request from account %s", short(acct))
		if name != "" {
			fmt.Printf(" (%q)", name)
		}
		fmt.Printf("\nfingerprint: %s\n", words)
		if *yes {
			fmt.Println("--yes: auto-confirmed")
			return true
		}
		return promptYes(fmt.Sprintf("confirm the SAME words show on their screen — add as %s? [y/N] ", *role))
	}
	inv, err := daemon.StartInviter(home, sp, *role, *lan, !*noMDNS, confirm)
	if err != nil {
		return err
	}
	defer inv.Close()

	fmt.Printf("invite code for space %q — tell it to your collaborator:\n\n", sp.Name)
	fmt.Printf("  lore join %s\n\n", inv.Code)
	fmt.Printf("(if mDNS discovery fails: lore join %s --addr <this-host>:%d)\n", inv.Code, inv.Port)
	fmt.Println("waiting for a join request; ctrl-c to abort")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	joined, err := inv.Wait(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.New("invite aborted")
		}
		return err
	}
	fmt.Printf("ok: added %s to %q as %s (member list v%d)\n",
		short(joined.Account), sp.Name, joined.Role, joined.DocV)
	fmt.Println("entries flow via normal sync (`lore serve` / `lore sync`)")
	return nil
}
