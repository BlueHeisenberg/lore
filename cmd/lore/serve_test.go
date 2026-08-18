package main

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestServeCommandHasNoDaemonOfItsOwn guards the one structural rule that
// keeps `lore serve` and the embeddable lore.(*Store).Serve honest: there is
// exactly one sync daemon in this module, internal/daemon, and both callers
// drive it. This file is the CLI half of that; test/serve is the library
// half, and TestCLIDaemonAndServeAreOneEngine there syncs the two against
// each other.
//
// What it forbids is the drift that would actually happen: someone fixing or
// extending the daemon on one side by growing a listener, a discovery loop or
// a sync round in the CLI. cmd/lore/serve.go is flags, prints and a signal
// wait, and it stays that.
func TestServeCommandHasNoDaemonOfItsOwn(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "serve.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	imports := map[string]bool{}
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		imports[path] = true
	}
	if !imports["github.com/BlueHeisenberg/lore/internal/daemon"] {
		t.Errorf("cmd/lore/serve.go no longer drives internal/daemon; imports = %v", importPaths(imports))
	}
	// Anything on this list is a piece of the daemon being rebuilt in the CLI.
	for _, forbidden := range []string{
		"github.com/BlueHeisenberg/agentmesh/pkg/transport",
		"github.com/BlueHeisenberg/agentmesh/pkg/discovery",
		"github.com/BlueHeisenberg/lore/internal/syncproto",
		"github.com/BlueHeisenberg/lore/internal/store",
		"net/http",
	} {
		if imports[forbidden] {
			t.Errorf("cmd/lore/serve.go imports %s: the CLI is growing its own sync daemon "+
				"instead of running internal/daemon's", forbidden)
		}
	}
}

func importPaths(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestServeCommandIsRegistered: the drift guard above is worthless if the
// command it inspects has been renamed out from under it.
func TestServeCommandIsRegistered(t *testing.T) {
	if _, ok := commands["serve"]; !ok {
		t.Fatalf("no `lore serve` command registered; registry has %s",
			strings.Join(commandOrder, " "))
	}
}
