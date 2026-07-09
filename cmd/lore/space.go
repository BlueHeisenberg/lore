package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/space"
	"github.com/BlueHeisenberg/lore/internal/store"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

func init() {
	register("space", "create/pin/invite shared topic spaces", cmdSpace)
}

func cmdSpace(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lore space create <name> | pin <space> [--off] | invite <space> [--role writer|reader] | invites [revoke <addr-prefix>]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdSpaceCreate(rest)
	case "pin":
		return cmdSpacePin(rest)
	case "invite":
		return cmdSpaceInvite(rest)
	case "invites":
		return cmdSpaceInvites(rest)
	default:
		return fmt.Errorf("unknown space subcommand %q (create|pin|invite|invites)", sub)
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
	expires := fs.Duration("expires", 6*time.Hour, "invite-link validity, at most 6h (link flow)")
	uses := fs.Int("uses", 1, "how many joiners may redeem the link, at most 10 (link flow)")
	lanFlow := fs.Bool("lan", false, "force the live LAN handshake instead of the relay link")
	yes := fs.Bool("yes", false, "LAN flow: skip the fingerprint confirmation prompt (automation)")
	noMDNS := fs.Bool("no-mdns", false, "LAN flow: do not advertise via mDNS (joiner must pass --addr)")
	timeout := fs.Duration("timeout", 10*time.Minute, "LAN flow: give up after this long")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore space invite <space> [--role writer|reader] [--expires 6h] [--uses 1] [--lan]")
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
	if err != nil {
		st.Close()
		return fmt.Errorf("space %q: %w", pos[0], err)
	}
	if sp.Kind == "personal" {
		st.Close()
		return errors.New("the personal space cannot be shared (lore enroll adds your own devices)")
	}

	// Default flow: async invite link through the relay. --lan (or no
	// configured relay) falls back to the live LAN handshake.
	if !*lanFlow {
		if relayclient.RelayURL(home) == "" {
			st.Close()
			fmt.Println("no relay configured — falling back to the live LAN handshake")
			fmt.Println("(set one up with `lore relay set-url <url>` or `lore signup` to mint async invite links)")
			return spaceInviteLAN(home, sp, *role, *yes, *noMDNS, *timeout)
		}
		defer st.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		tok, err := relayclient.MintInvite(ctx, home, st, sp, *role, *expires, *uses)
		if err != nil {
			return err
		}
		usesWord := "single use"
		if *uses > 1 {
			usesWord = fmt.Sprintf("%d uses", *uses)
		}
		fmt.Printf("invite link for space %q — send the token to your collaborator:\n\n", sp.Name)
		fmt.Printf("  lore join %s\n\n", tok.String())
		fmt.Printf("valid %s, %s, role %s — send it over a channel you trust; anyone holding it can join\n",
			*expires, usesWord, *role)
		fmt.Println("keep `lore serve` running on this device: it approves the join automatically")
		fmt.Println("(`lore space invites` lists open invites; `--lan` forces the old live handshake)")
		return nil
	}
	st.Close() // the LAN inviter opens its own handle
	return spaceInviteLAN(home, sp, *role, *yes, *noMDNS, *timeout)
}

// spaceInviteLAN is the original live LAN invite handshake, unchanged: it
// stays the no-relay path and the --lan escape hatch.
func spaceInviteLAN(home string, sp store.Space, role string, yes, noMDNS bool, timeout time.Duration) error {
	confirm := func(words, acct, name string) bool {
		fmt.Printf("\njoin request from account %s", short(acct))
		if name != "" {
			fmt.Printf(" (%q)", name)
		}
		fmt.Printf("\nfingerprint: %s\n", words)
		if yes {
			fmt.Println("--yes: auto-confirmed")
			return true
		}
		return promptYes(fmt.Sprintf("confirm the SAME words show on their screen — add as %s? [y/N] ", role))
	}
	inv, err := daemon.StartInviter(home, sp, role, true, !noMDNS, confirm)
	if err != nil {
		return err
	}
	defer inv.Close()

	fmt.Printf("invite code for space %q — tell it to your collaborator:\n\n", sp.Name)
	fmt.Printf("  lore join %s\n\n", inv.Code)
	fmt.Printf("(if mDNS discovery fails: lore join %s --addr <this-host>:%d)\n", inv.Code, inv.Port)
	fmt.Println("waiting for a join request; ctrl-c to abort")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

// cmdSpaceInvites lists this device's open invite links and revokes them.
//
//	lore space invites
//	lore space invites revoke <addr-prefix>
func cmdSpaceInvites(args []string) error {
	fs := flag.NewFlagSet("space invites", flag.ContinueOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	if len(pos) >= 1 && pos[0] == "revoke" {
		if len(pos) != 2 {
			return errors.New("usage: lore space invites revoke <addr-prefix>")
		}
		li, err := relayclient.FindLocalInvite(db, pos[1])
		if err != nil {
			return err
		}
		device, err := keys.LoadDevice(home)
		if err != nil {
			return err
		}
		c, err := relayclient.New(relayclient.RelayURL(home), device)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := c.RevokeInvite(ctx, li.Addr); err != nil && !relayclient.IsNotFound(err) {
			return err
		}
		if err := relayclient.DeleteLocalInvite(db, li.Addr); err != nil {
			return err
		}
		fmt.Printf("ok: revoked invite %s\n", short(li.Addr))
		return nil
	}
	if len(pos) != 0 {
		return errors.New("usage: lore space invites [revoke <addr-prefix>]")
	}

	invites, err := relayclient.ListLocalInvites(db)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	names := map[string]string{}
	if st, _, _, err := openStore(home); err == nil {
		names = spaceNames(st)
		st.Close()
	}
	open := 0
	for _, li := range invites {
		if li.ExpiresAt <= now {
			continue // expired; the daemon prunes these
		}
		open++
		name := names[li.SpaceID]
		if name == "" {
			name = short(li.SpaceID)
		}
		fmt.Printf("%s  %-12s %-7s uses-left %d  age %s  expires in %s\n",
			short(li.Addr), name, li.Role, li.UsesLeft,
			(time.Duration(now-li.CreatedAt) * time.Second).Round(time.Second),
			(time.Duration(li.ExpiresAt-now) * time.Second).Round(time.Second))
	}
	if open == 0 {
		fmt.Println("no open invites (`lore space invite <space>` mints one)")
	}
	return nil
}
