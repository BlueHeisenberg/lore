//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// addToPath makes lore reachable on Unix by symlinking it into ~/.local/bin,
// which is on PATH by default on modern Linux and macOS.
//
// Deliberately not an edit to a shell rc file: there are too many shells to
// pick the right one, the edit is hard to undo, and getting it wrong breaks
// the user's login shell. A symlink is one file, and `rm` undoes it.
func addToPath(exe, dir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	localBin := filepath.Join(home, ".local", "bin")
	link := filepath.Join(localBin, filepath.Base(exe))

	switch target, lerr := os.Readlink(link); {
	case lerr == nil && target == exe:
		fmt.Printf("path: %s already links to %s\n", link, exe)
	case lerr == nil:
		return fmt.Errorf("%s already links to %s, not %s — remove it first", link, target, exe)
	default:
		if _, serr := os.Stat(link); serr == nil {
			return fmt.Errorf("%s already exists and is not a symlink — remove it first", link)
		}
		if err := os.MkdirAll(localBin, 0o755); err != nil {
			return err
		}
		if err := os.Symlink(exe, link); err != nil {
			return err
		}
		fmt.Printf("path: %s is not on PATH; linked %s -> %s — restart any open shells\n", dir, link, exe)
	}

	// Don't guess at rc files if ~/.local/bin isn't searched either: print
	// the exact line and let the user place it.
	if !pathContains(os.Getenv("PATH"), localBin) {
		fmt.Printf("path: %s is not on PATH either — add this line to your shell profile:\n\n  export PATH=\"%s:$PATH\"\n\n", localBin, localBin)
	}
	return nil
}
