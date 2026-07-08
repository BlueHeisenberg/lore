// lore-relay is the hosted-state relay server (docs/RELAY.md): one binary,
// SQLite + blob dir, zero knowledge of plaintext.
//
//	lore-relay serve                          run the HTTP server (env config
//	                                          per configs/env.example)
//	lore-relay admin set-plan <account> <plan> [--data DIR]
//	lore-relay admin stats [--data DIR]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BlueHeisenberg/lore/internal/relay"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "lore-relay:", err)
			os.Exit(1)
		}
	case "admin":
		if err := runAdmin(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "lore-relay:", err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "lore-relay: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  lore-relay serve                              run the relay (env: LORE_RELAY_ADDR,
                                                LORE_RELAY_DATA, LORE_RELAY_QUOTA_MB,
                                                STRIPE_WEBHOOK_SECRET, ...)
  lore-relay admin set-plan <account_pub> <free|trial|paid> [--data DIR]
  lore-relay admin stats [--data DIR]`)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := relay.ConfigFromEnv()
	if cfg.DataDir == "" {
		return errors.New("LORE_RELAY_DATA must be set")
	}
	// Request log to stderr: method path status bytes ms — never bodies.
	logger := log.New(os.Stderr, "", log.LstdFlags)
	srv, err := relay.NewServer(cfg, logger)
	if err != nil {
		return err
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("lore-relay listening on %s (data: %s, quota: %d MB, stripe: %v)",
			cfg.Addr, cfg.DataDir, cfg.QuotaMB, cfg.StripeWebhookSecret != "")
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Println("lore-relay shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

func runAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("admin: expected subcommand set-plan or stats")
	}
	sub := args[0]
	rest := args[1:]

	// Accept --data anywhere after the subcommand; positional args first.
	fs := flag.NewFlagSet("admin "+sub, flag.ExitOnError)
	dataDir := fs.String("data", os.Getenv("LORE_RELAY_DATA"), "relay data dir (relay.db + blobs)")
	var positional []string
	for len(rest) > 0 {
		if len(rest[0]) > 1 && rest[0][0] == '-' {
			if err := fs.Parse(rest); err != nil {
				return err
			}
			positional = append(positional, fs.Args()...)
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	if *dataDir == "" {
		return errors.New("admin: --data (or LORE_RELAY_DATA) is required")
	}

	switch sub {
	case "set-plan":
		if len(positional) != 2 {
			return errors.New("usage: lore-relay admin set-plan <account_pub> <free|trial|paid> [--data DIR]")
		}
		if err := relay.AdminSetPlan(*dataDir, positional[0], positional[1]); err != nil {
			return err
		}
		fmt.Printf("plan for %s set to %s\n", positional[0], positional[1])
		return nil
	case "stats":
		return relay.AdminStats(*dataDir, os.Stdout)
	default:
		return fmt.Errorf("admin: unknown subcommand %q", sub)
	}
}
