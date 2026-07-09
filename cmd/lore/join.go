package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
)

func init() {
	register("join", "accept a LAN space invite by code", cmdJoin)
}

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	addr := fs.String("addr", "", "inviter address host:port (default: find via mDNS)")
	yes := fs.Bool("yes", false, "skip the fingerprint confirmation prompt (automation)")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up after this long")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore join <code> [--addr host:port]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}

	confirm := func(words, inviterAccount, _ string) bool {
		fmt.Printf("inviter account %s\n", short(inviterAccount))
		fmt.Printf("fingerprint: %s\n", words)
		if *yes {
			fmt.Println("--yes: auto-confirmed")
			return true
		}
		return promptYes("confirm the SAME words show on the inviter's screen — join? [y/N] ")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := daemon.Join(ctx, home, pos[0], *addr, confirm)
	if err != nil {
		return err
	}
	fmt.Printf("ok: joined space %q as %s (%d members, invited by %s)\n",
		res.Space.Name, res.Role, res.Members, short(res.InviterAccount))
	fmt.Println("entries flow via normal sync — make sure the daemons see each other (`lore peer add <host:port>` if needed)")
	return nil
}
