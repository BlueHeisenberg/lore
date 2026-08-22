package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pick returns the Windows or the Unix spelling of a path, so the table below
// reads once and runs on both.
func pick(win, unix string) string {
	if runtime.GOOS == "windows" {
		return win
	}
	return unix
}

func join(entries ...string) string {
	return strings.Join(entries, string(os.PathListSeparator))
}

func TestPathContains(t *testing.T) {
	var (
		bin      = pick(`C:\Users\me\bin`, "/home/me/bin")
		bin2     = pick(`C:\Users\me\bin2`, "/home/me/bin2")
		other    = pick(`C:\Windows\System32`, "/usr/bin")
		windowsy = runtime.GOOS == "windows"
	)
	cases := []struct {
		name string
		path string
		dir  string
		want bool
	}{
		{"empty PATH", "", bin, false},
		{"empty dir", join(other, bin), "", false},
		{"exact match", join(other, bin), bin, true},
		{"absent", join(other, bin2), bin, false},
		{"substring of a longer entry", join(other, bin2), bin, false},
		{"trailing separator on the entry", join(other, bin+string(filepath.Separator)), bin, true},
		{"trailing separator on the dir", join(other, bin), bin + string(filepath.Separator), true},
		{"surrounding spaces", join(other, "  "+bin+"  "), bin, true},
		{"case difference", join(other, strings.ToUpper(bin)), bin, windowsy},
		{"only entry", bin, bin, true},
		{"empty entries around it", join("", bin, ""), bin, true},
	}
	for _, c := range cases {
		if got := pathContains(c.path, c.dir); got != c.want {
			t.Errorf("%s: pathContains(%q, %q) = %v, want %v", c.name, c.path, c.dir, got, c.want)
		}
	}
}

func TestPathContainsQuotedEntry(t *testing.T) {
	// Windows PATH values may quote an entry; filepath.SplitList strips the
	// quotes there, normPathEntry strips them everywhere else.
	bin := pick(`C:\Users\me\bin`, "/home/me/bin")
	if !pathContains(join(pick(`C:\Windows`, "/usr/bin"), `"`+bin+`"`), bin) {
		t.Errorf("quoted entry %q not matched", bin)
	}
}

func TestNormPathEntryKeepsRoot(t *testing.T) {
	root := pick(`\`, "/")
	if got := normPathEntry(root); got != root {
		t.Errorf("normPathEntry(%q) = %q, want %q", root, got, root)
	}
}
