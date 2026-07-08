package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/BlueHeisenberg/lore/internal/daemon"
	"github.com/BlueHeisenberg/lore/internal/syncproto"
)

func init() { register("peer", "manage static sync peers (add <host:port> | list)", cmdPeer) }

func cmdPeer(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lore peer add <host:port> | lore peer list")
	}
	sub, rest := args[0], args[1:]
	home, err := loreHome()
	if err != nil {
		return err
	}
	switch sub {
	case "add":
		fs := flag.NewFlagSet("peer add", flag.ContinueOnError)
		pos, err := parseArgs(fs, rest)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return errors.New("usage: lore peer add <host:port>")
		}
		p, err := daemon.AddStaticPeer(home, pos[0])
		if err != nil {
			return err
		}
		fmt.Printf("pinned peer %s (%s) account %s at %s\n",
			short(p.DeviceID), p.Name, short(p.AccountPub), p.Addr)
		fmt.Println("note: first contact is trust-on-first-use; future syncs require this exact device key")
		return nil
	case "list":
		db, err := syncproto.OpenDB(filepath.Join(home, "lore.db"))
		if err != nil {
			return err
		}
		defer db.Close()
		peers, err := syncproto.ListPeers(db)
		if err != nil {
			return err
		}
		if len(peers) == 0 {
			fmt.Println("no peers")
			return nil
		}
		for _, p := range peers {
			kind := "mdns"
			if p.Static {
				kind = "static"
			}
			fmt.Printf("%s  %-7s %-16s acct:%s  %s  last seen %s\n",
				short(p.DeviceID), kind, p.Name, short(p.AccountPub), p.Addr, p.LastSeen)
		}
		return nil
	default:
		return fmt.Errorf("unknown peer subcommand %q (add|list)", sub)
	}
}
