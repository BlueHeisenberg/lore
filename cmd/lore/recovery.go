package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/BlueHeisenberg/lore/internal/keys"
	"github.com/BlueHeisenberg/lore/internal/relayclient"
	"github.com/BlueHeisenberg/lore/internal/vault"
)

func init() {
	register("recovery", "mint a new recovery code (voids the old one)", cmdRecovery)
}

// cmdRecovery implements `lore recovery new`. The recovery code is a KDF
// factor, never stored: minting a new one only matters for what gets wrapped
// AFTER it. If a relay keybox exists, it is re-sealed under the new code
// immediately (requires the passphrase), which is what actually voids a
// leaked code; without a keybox there is nothing to re-wrap and the new code
// simply becomes the one to use at signup/backup.
func cmdRecovery(args []string) error {
	fs := flag.NewFlagSet("recovery", flag.ContinueOnError)
	passphrase := fs.String("passphrase", "", "account passphrase (required only when a relay keybox must be re-sealed)")
	yes := fs.Bool("yes-i-saved-it", false, "skip the re-type confirmation (automation)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || pos[0] != "new" {
		return errors.New("usage: lore recovery new [--passphrase ...]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	if _, err := keys.LoadAccount(home); err != nil {
		return err
	}

	code, err := keys.NewRecoveryCode()
	if err != nil {
		return err
	}
	fmt.Printf("new recovery code — shown once, store it in a password manager:\n\n  %s\n\n", code)
	if !*yes {
		fmt.Print("re-type the new code to confirm you saved it: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("not confirmed — nothing changed, run `lore recovery new` again")
		}
		if keys.NormalizeRecoveryCode(line) != keys.NormalizeRecoveryCode(code) {
			return errors.New("mismatch — nothing changed, run `lore recovery new` again")
		}
	}

	// Re-seal the relay keybox if one exists; otherwise the new code simply
	// takes effect at the next signup/backup.
	url := relayclient.RelayURL(home)
	if url == "" {
		fmt.Println("no relay configured: nothing was wrapped under any previous code.")
		fmt.Println("use THIS code for `lore signup` and `lore backup`; any earlier code is now meaningless.")
		return nil
	}
	if *passphrase == "" {
		return errors.New("a relay is configured, so the keybox must be re-sealed: rerun with --passphrase")
	}
	wk, err := relayclient.DeriveWrapKey(*passphrase, code, vault.DefaultKDF)
	if err != nil {
		return err
	}
	payload, err := relayclient.BuildKeyboxPayload(home)
	if err != nil {
		return err
	}
	envelope, err := relayclient.SealKeyboxWithKey(payload, wk)
	if err != nil {
		return err
	}
	device, err := keys.LoadDevice(home)
	if err != nil {
		return err
	}
	client, err := relayclient.New(url, device)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.PutKeybox(ctx, envelope); err != nil {
		return fmt.Errorf("upload re-sealed keybox: %w", err)
	}
	if err := relayclient.SaveWrapKey(home, wk); err != nil {
		return err
	}
	fmt.Println("ok: keybox re-sealed and uploaded — the old recovery code (and old passphrase pairing) is now useless everywhere.")
	fmt.Println("note: re-run `lore backup` if you keep offline archives; old archives still open with the OLD code.")
	return nil
}
