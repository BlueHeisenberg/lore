package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/invite"
	"github.com/BlueHeisenberg/lore/internal/relayclient"
)

func init() {
	register("join", "accept a space invite (link token or LAN code)", cmdJoin)
}

// cmdJoin accepts both invite shapes and picks the flow by format:
//   - invite-link token (four words + 2-digit number, e.g.
//     maple-rocket-sunset-cactus-73) -> async relay flow
//   - 8-char LAN code -> the original live handshake
func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	relayURL := fs.String("relay", "", "relay base URL for link tokens (default: config relay_url)")
	addr := fs.String("addr", "", "LAN flow: inviter address host:port (default: find via mDNS)")
	yes := fs.Bool("yes", false, "LAN flow: skip the fingerprint confirmation prompt (automation)")
	timeout := fs.Duration("timeout", 5*time.Minute, "give up after this long")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: lore join <token|code> [--relay <url>] [--addr host:port]")
	}
	// Tokens read naturally with spaces too: `lore join maple rocket sunset cactus 73`.
	code := pos[0]
	if len(pos) > 1 {
		joined := pos[0]
		for _, p := range pos[1:] {
			joined += " " + p
		}
		if invite.IsToken(joined) {
			code = joined
		} else {
			return errors.New("usage: lore join <token|code> [--relay <url>] [--addr host:port]")
		}
	}
	home, err := loreHome()
	if err != nil {
		return err
	}

	if invite.IsToken(code) {
		return joinWithToken(home, code, *relayURL)
	}

	// --- LAN code: the original live handshake, unchanged ---
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
	res, err := daemon.Join(ctx, home, code, *addr, confirm)
	if err != nil {
		return err
	}
	fmt.Printf("ok: joined space %q as %s (%d members, invited by %s)\n",
		res.Space.Name, res.Role, res.Members, short(res.InviterAccount))
	fmt.Println("entries flow via normal sync — make sure the daemons see each other (`lore peer add <host:port>` if needed)")
	return nil
}

// joinWithToken runs the async invite-link flow: redeem the payload, store
// the space, park the claim, and wait briefly for the owner's daemon to
// admit us.
func joinWithToken(home, token, relayFlag string) error {
	url := relayFlag
	if url == "" {
		url = relayclient.RelayURL(home)
	}
	if url == "" {
		return errors.New("invite links need a relay: pass --relay <url> (ask the inviter for theirs)")
	}
	// Redeem + poll for the membership doc; the poll is capped at ~30s
	// because the owner's daemon may simply be offline right now.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := relayclient.JoinInvite(ctx, home, url, token, 30*time.Second)
	if err != nil {
		return err
	}
	if res.Pending {
		fmt.Printf("joined %q — membership pending the owner's device coming online; `lore serve` will complete it\n",
			res.SpaceName)
		fmt.Println("(the space is stored locally; entries start flowing once the owner's daemon approves the claim)")
		return nil
	}
	fmt.Printf("ok: joined space %q as %s (%d members)\n", res.SpaceName, res.Role, res.Members)
	fmt.Println("entries flow via the relay — keep `lore serve` running (or run `lore sync` after writes)")
	return nil
}
