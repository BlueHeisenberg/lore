package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
)

func init() { register("serve", "run the sync daemon", cmdServe) }

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	lan := fs.Bool("lan", false, "advertise/browse on LAN interfaces and bind 0.0.0.0 (default: loopback only)")
	adminPort := fs.Int("admin-port", 0, "admin API port on 127.0.0.1 (default: ephemeral)")
	noMDNS := fs.Bool("no-mdns", false, "disable mDNS discovery (static peers only)")
	port := fs.Int("port", 0, "fixed mTLS sync port (default: ephemeral); set one when peers reach you via a static address, e.g. over Tailscale")
	interval := fs.Duration("interval", 30*time.Second, "sync interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	d, err := daemon.New(home, daemon.Options{
		LAN:          *lan,
		NoMDNS:       *noMDNS,
		AdminPort:    *adminPort,
		SyncPort:     *port,
		SyncInterval: *interval,
		Logf: func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "lore serve: "+format+"\n", a...)
		},
	})
	if err != nil {
		return err
	}
	if err := d.Start(); err != nil {
		return err
	}
	scope := "loopback"
	if *lan {
		scope = "LAN"
	}
	fmt.Printf("device   %s\n", d.DeviceID())
	fmt.Printf("sync     mTLS on port %d (%s)\n", d.Port(), scope)
	fmt.Printf("admin    127.0.0.1:%d (token in daemon.json)\n", d.AdminPort())
	fmt.Println("serving; ctrl-c to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("\nshutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d.Stop(ctx)
	return nil
}
