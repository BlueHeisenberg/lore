package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BlueHeisenberg/lore/internal/vault"
)

func init() {
	register("backup", "write an encrypted backup archive", cmdBackup)
	register("restore", "restore a backup archive into a fresh LORE_HOME", cmdRestore)
}

// promptSecret reads a line from stdin when a secret was not passed by flag.
// (Plain echo read; passphrases-without-echo needs x/term, deferred to keep
// the dependency list tight. Automation always passes flags.)
func promptSecret(label string) (string, error) {
	fmt.Printf("%s: ", label)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("%s required (or pass it by flag)", label)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("%s must not be empty", label)
	}
	return line, nil
}

func secretArgs(passFlag, recoveryFlag string) (string, string, error) {
	pass, recovery := passFlag, recoveryFlag
	var err error
	if pass == "" {
		if pass, err = promptSecret("passphrase"); err != nil {
			return "", "", err
		}
	}
	if recovery == "" {
		if recovery, err = promptSecret("recovery code"); err != nil {
			return "", "", err
		}
	}
	return pass, recovery, nil
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	pass := fs.String("passphrase", "", "archive passphrase (prompted if omitted)")
	recovery := fs.String("recovery-code", "", "account recovery code (prompted if omitted)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore backup <file> [--passphrase ..] [--recovery-code ..]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	p, r, err := secretArgs(*pass, *recovery)
	if err != nil {
		return err
	}
	env, err := vault.Backup(home, p, r, vault.DefaultKDF)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pos[0], env, 0o600); err != nil {
		return err
	}
	fmt.Printf("ok: encrypted backup written to %s (%d bytes)\n", pos[0], len(env))
	fmt.Println("restoring needs BOTH the passphrase and the recovery code")
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	pass := fs.String("passphrase", "", "archive passphrase (prompted if omitted)")
	recovery := fs.String("recovery-code", "", "account recovery code (prompted if omitted)")
	name := fs.String("name", "", "name for the new device (default: hostname)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: lore restore <file> [--passphrase ..] [--recovery-code ..] [--name ..]")
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	env, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	p, r, err := secretArgs(*pass, *recovery)
	if err != nil {
		return err
	}
	if *name == "" {
		if *name, err = os.Hostname(); err != nil || *name == "" {
			*name = "restored"
		}
	}
	if err := vault.Restore(home, env, p, r, *name); err != nil {
		return err
	}
	fmt.Printf("ok: restored account into %s with new device %q\n", home, *name)
	return nil
}
