package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestServerName(t *testing.T) {
	tests := []struct {
		baseURL string
		email   string
		want    string
	}{
		{"https://pwdsafe.example.com", "user@example.com", "pwdsafe.example.com (user@example.com)"},
		{"https://pwdsafe.example.com/", "user@example.com", "pwdsafe.example.com (user@example.com)"},
		{"http://localhost:8080", "user@example.com", "localhost:8080 (user@example.com)"},
		{"https://pwdsafe.example.com:8443/api", "user@example.com", "pwdsafe.example.com:8443 (user@example.com)"},
		{"not a url", "user@example.com", "not a url (user@example.com)"},
		{"https://pwdsafe.example.com", "", "pwdsafe.example.com"},
	}

	for _, tt := range tests {
		if got := ServerName(tt.baseURL, tt.email); got != tt.want {
			t.Errorf("ServerName(%q, %q) = %q, want %q", tt.baseURL, tt.email, got, tt.want)
		}
	}
}

func TestLoadMigratesLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	accent := "#FF5FAF"
	legacy := map[string]any{
		"base_url":     "https://pwdsafe.example.com",
		"email":        "user@example.com",
		"token":        "tok123",
		"accent_color": accent,
	}

	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy config: %v", err)
	}

	configDir := filepath.Join(dir, "pwdsafe-cli")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(configDir, "config.json"), data, 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Servers) != 1 {
		t.Fatalf("Servers = %v, want 1 entry", cfg.Servers)
	}

	const wantName = "pwdsafe.example.com (user@example.com)"

	srv := cfg.Servers[0]
	if srv.Name != wantName || srv.BaseURL != "https://pwdsafe.example.com" || srv.Email != "user@example.com" || srv.Token != "tok123" {
		t.Errorf("migrated server = %+v", srv)
	}

	if cfg.ActiveServer != wantName {
		t.Errorf("ActiveServer = %q, want %q", cfg.ActiveServer, wantName)
	}

	if cfg.AccentColor == nil || *cfg.AccentColor != accent {
		t.Errorf("AccentColor = %v, want %q", cfg.AccentColor, accent)
	}

	if cfg.BaseURL != "" || cfg.Email != "" || cfg.Token != "" {
		t.Errorf("legacy fields not cleared: %+v", cfg)
	}

	// Reload to confirm the migrated shape was persisted.
	reloaded, err := Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if len(reloaded.Servers) != 1 || reloaded.ActiveServer != wantName {
		t.Errorf("reloaded config not normalized: %+v", reloaded)
	}

	if reloaded.AccentColor == nil || *reloaded.AccentColor != accent {
		t.Errorf("reloaded AccentColor = %v, want %q", reloaded.AccentColor, accent)
	}
}

func TestUpsertServer(t *testing.T) {
	cfg := &Config{}

	cfg.UpsertServer(Server{Name: "a.example.com", Email: "a@example.com"})
	cfg.UpsertServer(Server{Name: "b.example.com", Email: "b@example.com"})

	if len(cfg.Servers) != 2 {
		t.Fatalf("Servers = %v, want 2 entries", cfg.Servers)
	}

	// Updating an existing server (same host name) replaces in place rather
	// than appending a duplicate.
	cfg.UpsertServer(Server{Name: "a.example.com", Email: "new-a@example.com"})

	if len(cfg.Servers) != 2 {
		t.Fatalf("Servers = %v, want 2 entries after update", cfg.Servers)
	}

	srv, idx := cfg.FindServer("a.example.com")
	if idx != 0 || srv.Email != "new-a@example.com" {
		t.Errorf("FindServer(a.example.com) = %+v, idx %d", srv, idx)
	}
}

func TestRemoveServer(t *testing.T) {
	cfg := &Config{
		Servers: []Server{
			{Name: "a.example.com"},
			{Name: "b.example.com"},
		},
		ActiveServer: "a.example.com",
	}

	if err := cfg.RemoveServer("a.example.com"); err != nil {
		t.Fatalf("RemoveServer: %v", err)
	}

	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "b.example.com" {
		t.Errorf("Servers = %v after removal", cfg.Servers)
	}

	if err := cfg.RemoveServer("nope.example.com"); err == nil {
		t.Error("RemoveServer(unknown) = nil, want error")
	}
}

func TestActive(t *testing.T) {
	cfg := &Config{
		Servers: []Server{
			{Name: "a.example.com"},
			{Name: "b.example.com"},
		},
		ActiveServer: "b.example.com",
	}

	srv := cfg.Active()
	if srv == nil || srv.Name != "b.example.com" {
		t.Errorf("Active() = %+v, want b.example.com", srv)
	}

	cfg.ActiveServer = "unknown"
	if cfg.Active() != nil {
		t.Errorf("Active() = %+v, want nil for unknown ActiveServer", cfg.Active())
	}
}
