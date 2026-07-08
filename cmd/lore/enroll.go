package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BlueHeisenberg/lore/internal/daemon"
)

func init() {
	register("enroll", "enroll THIS new device into an existing account (LAN)", cmdEnroll)
	register("approve", "approve an enrolling device from THIS existing device", cmdApprove)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	name := fs.String("name", "", "device name (default: hostname)")
	lan := fs.Bool("lan", true, "listen on LAN interfaces (default true; enrollment is a LAN flow)")
	noMDNS := fs.Bool("no-mdns", false, "do not advertise via mDNS (approver must pass --addr)")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	if *name == "" {
		if *name, err = os.Hostname(); err != nil || *name == "" {
			*name = "device"
		}
	}
	e, err := daemon.StartEnrollee(home, *name, *lan, !*noMDNS)
	if err != nil {
		return err
	}
	defer e.Close()

	fmt.Printf("enrolling %q — on a device that already has this account, run:\n\n", *name)
	fmt.Printf("  lore approve %s\n\n", e.Code)
	fmt.Printf("(if mDNS discovery fails: lore approve %s --addr <this-host>:%d)\n", e.Code, e.Port)
	fmt.Printf("channel key %s\n", e.EphPub)
	fmt.Println("waiting for approval; ctrl-c to abort")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	if err := e.Wait(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return errors.New("enrollment aborted")
		}
		return err
	}
	fmt.Printf("ok: enrolled into account; home %s ready (start `lore serve` to sync)\n", home)
	return nil
}

func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	addr := fs.String("addr", "", "enrollee address host:port (default: find via mDNS)")
	timeout := fs.Duration("timeout", 30*time.Second, "give up after this long")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore approve <code> [--addr host:port]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	deviceID, err := daemon.Approve(ctx, home, pos[0], *addr)
	if err != nil {
		return err
	}
	fmt.Printf("ok: enrolled device %s\n", short(deviceID))
	fmt.Println("tip: `lore peer add <host>:<sync-port>` or shared mDNS will connect it")
	return nil
}
