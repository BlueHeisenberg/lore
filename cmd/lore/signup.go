package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/vault"
)

func init() {
	register("signup", "claim a relay handle and upload the encrypted keybox", cmdSignup)
}

// relayURLArg resolves the relay URL: --relay flag first, then config.json.
func relayURLArg(home, flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if u := relayclient.RelayURL(home); u != "" {
		return u, nil
	}
	return "", relayclient.ErrNoRelay
}

// cmdSignup connects an existing account (`lore init` must have run) to a
// relay: enroll device, claim handle, upload the keybox (account keys +
// spaces manifest wrapped under Argon2id(passphrase+recovery code)), and
// register every local space.
func cmdSignup(args []string) error {
	fs := flag.NewFlagSet("signup", flag.ContinueOnError)
	handle := fs.String("handle", "", "relay handle to claim, [a-z0-9-]{3,32} (required)")
	relayURL := fs.String("relay", "", "relay base URL, e.g. https://relay.example.com (default: config relay_url)")
	pass := fs.String("passphrase", "", "keybox passphrase (prompted if omitted)")
	recovery := fs.String("recovery-code", "", "account recovery code from `lore init` (prompted if omitted)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *handle == "" {
		return errors.New("usage: lore signup --handle <h> [--relay <url>] [--passphrase ..] [--recovery-code ..]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	url, err := relayURLArg(home, *relayURL)
	if err != nil {
		return err
	}
	p, r, err := secretArgs(*pass, *recovery)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := relayclient.Signup(ctx, home, url, *handle, p, r, vault.DefaultKDF); err != nil {
		return err
	}
	fmt.Printf("ok: signed up as @%s on %s\n", *handle, url)
	fmt.Println("keybox uploaded — `lore login` on any machine needs the handle, passphrase AND recovery code")
	fmt.Println("start (or restart) `lore serve` to keep this device syncing through the relay")
	return nil
}
