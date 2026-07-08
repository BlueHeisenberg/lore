package main

import (
	"flag"

	"github.com/BlueHeisenberg/lore/internal/mcpserver"
)

func init() { register("mcp", "stdio MCP server", cmdMCP) }

// cmdMCP serves lore's MCP tools on stdio until the client disconnects.
// LORE_HOME resolution is identical to the rest of the CLI.
func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	home, err := loreHome()
	if err != nil {
		return err
	}
	return mcpserver.Serve(home)
}
