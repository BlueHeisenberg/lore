package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/vault"
)

func init() {
	register("login", "provision this fresh device from a relay account", cmdLogin)
}

// cmdLogin is the fresh-device flow: NO account.json may exist. It fetches
// the keybox by handle (unauthenticated relay route), unwraps it locally
// with passphrase + recovery code, restores the account and the spaces
// manifest, mints and enrolls a new device, then pulls every space's
// snapshot + log so search works immediately.
func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	handle := fs.String("handle", "", "relay handle of the account (required)")
	relayURL := fs.String("relay", "", "relay base URL (required)")
	pass := fs.String("passphrase", "", "keybox passphrase (prompted if omitted)")
	recovery := fs.String("recovery-code", "", "account recovery code (prompted if omitted)")
	name := fs.String("name", "", "name for this new device (default: hostname)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *handle == "" || *relayURL == "" {
		return errors.New("usage: lore login --handle <h> --relay <url> [--passphrase ..] [--recovery-code ..] [--name ..]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	p, r, err := secretArgs(*pass, *recovery)
	if err != nil {
		return err
	}
	if *name == "" {
		if *name, err = os.Hostname(); err != nil || *name == "" {
			*name = "device"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := relayclient.Login(ctx, home, *relayURL, *handle, p, r, *name, vault.DefaultKDF)
	if err != nil {
		return err
	}
	fmt.Printf("account  %s\n", res.AccountID)
	fmt.Printf("device   %s (%s)\n", res.DeviceID, *name)
	fmt.Printf("ok: logged in as @%s — %d spaces restored, %d entries pulled into %s\n",
		*handle, res.Spaces, res.Entries, home)
	fmt.Println("`lore search` works now; run `lore serve` to keep syncing")
	return nil
}
