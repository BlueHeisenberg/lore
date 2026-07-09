package relayclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// config.json is shared JSON: cmd/lore's own loader marshals only the fields
// it knows, so THIS package must never rewrite the file through a typed
// struct. Reads use a local struct (unknown fields ignored); writes go
// through a map[string]any so every key other agents/commands put there is
// preserved verbatim.

// RelayURL returns the relay_url from LORE_HOME/config.json ("" = relay off).
func RelayURL(home string) string {
	b, err := os.ReadFile(filepath.Join(home, "config.json"))
	if err != nil {
		return ""
	}
	var cfg struct {
		RelayURL string `json:"relay_url"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return ""
	}
	return cfg.RelayURL
}

// SetConfigValue sets one key in LORE_HOME/config.json, creating the file if
// absent and preserving all other keys (raw map round-trip, never a struct).
func SetConfigValue(home, key string, value any) error {
	path := filepath.Join(home, "config.json")
	raw := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("config.json is not valid JSON, refusing to overwrite: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw[key] = value
	b, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// SetRelayURL persists the relay URL into config.json.
func SetRelayURL(home, url string) error { return SetConfigValue(home, "relay_url", url) }
