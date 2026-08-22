package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func init() {
	register("path", "add lore's directory to your PATH", cmdPath)
}

func cmdPath(args []string) error {
	fs := flag.NewFlagSet("path", flag.ContinueOnError)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	return ensureOnPath()
}

// ensureOnPath makes the directory holding the running binary reachable by
// name from a fresh shell. It is idempotent: the second run finds the entry
// and writes nothing. Installing lore somewhere PowerShell does not search
// (git-bash adds ~/bin, PowerShell does not) leaves a working store nobody
// can invoke, so init does this too.
func ensureOnPath() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	if pathContains(os.Getenv("PATH"), dir) {
		fmt.Printf("path: %s is already on PATH\n", dir)
		return nil
	}
	return addToPath(exe, dir)
}

// pathContains reports whether dir is already an entry of a PATH-style value.
// Entry-by-entry equality, never substring: C:\bin must not match C:\bin2.
func pathContains(pathValue, dir string) bool {
	want := normPathEntry(dir)
	if want == "" {
		return false
	}
	for _, entry := range filepath.SplitList(pathValue) {
		if normPathEntry(entry) == want {
			return true
		}
	}
	return false
}

// normPathEntry canonicalises one PATH entry: surrounding space and quotes
// off, trailing separators off, case folded on Windows.
func normPathEntry(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	s = strings.TrimSpace(s)
	for len(s) > 1 && os.IsPathSeparator(s[len(s)-1]) {
		s = s[:len(s)-1]
	}
	if runtime.GOOS == "windows" {
		s = strings.ToLower(filepath.FromSlash(s))
	}
	return s
}
