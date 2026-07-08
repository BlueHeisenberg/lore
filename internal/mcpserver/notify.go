package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/BlueHeisenberg/lore/internal/distill"
)

// afterWrite runs the post-write side effects, best-effort and errors
// ignored: poke the daemon to sync, and re-render the distill mirror when
// the write touched the personal space.
func (s *Server) afterWrite(spaceID string) {
	s.pokeDaemon()
	s.maybeRenderDistill(spaceID)
}

// pokeDaemon fires POST /admin/sync at the local daemon if daemon.json
// exists ({"port":N,"token":"s"}). Fire-and-forget: 1s timeout, errors
// ignored — the daemon is optional.
func (s *Server) pokeDaemon() {
	b, err := os.ReadFile(filepath.Join(s.home, "daemon.json"))
	if err != nil {
		return
	}
	var d struct {
		Port  int    `json:"port"`
		Token string `json:"token"`
	}
	if json.Unmarshal(b, &d) != nil || d.Port <= 0 {
		return
	}
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/admin/sync?token=%s",
		d.Port, url.QueryEscape(d.Token)), "", nil)
	if err == nil {
		resp.Body.Close()
	}
}

// maybeRenderDistill re-renders the distill mirror after a personal-space
// write, but only when config.json explicitly sets distill_dir — the MCP
// server never assumes the real ~/.claude/distill on its own. Errors ignored.
func (s *Server) maybeRenderDistill(spaceID string) {
	personal, err := s.st.PersonalSpace()
	if err != nil || personal.SpaceID != spaceID {
		return
	}
	b, err := os.ReadFile(filepath.Join(s.home, "config.json"))
	if err != nil {
		return
	}
	var c struct {
		DistillDir string `json:"distill_dir"`
	}
	if json.Unmarshal(b, &c) != nil || c.DistillDir == "" {
		return
	}
	_, _ = distill.Render(s.st, personal.SpaceID, c.DistillDir)
}
