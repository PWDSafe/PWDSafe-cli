// Package config handles loading and saving the CLI's local configuration
// file, which stores the API base URL and the Sanctum token issued at login.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// Server holds the connection details and credentials for a single PWDSafe
// server/account.
type Server struct {
	// Name identifies the server, derived from its BaseURL's host (e.g.
	// "pwdsafe.example.com"). Used to select it via `servers use <name>` and
	// in the TUI server picker.
	Name             string  `json:"name"`
	BaseURL          string  `json:"base_url"`
	Email            string  `json:"email"`
	Token            string  `json:"token"`
	EncryptedPrivKey *string `json:"encrypted_privkey,omitempty"`
	PrivKeySalt      *string `json:"privkey_salt,omitempty"`
}

// Config is the on-disk shape of ~/.config/pwdsafe-cli/config.json.
type Config struct {
	// Servers is the list of configured PWDSafe servers/accounts.
	Servers []Server `json:"servers,omitempty"`

	// ActiveServer is the Name of the server currently in use.
	ActiveServer string `json:"active_server,omitempty"`

	// Legacy single-server fields, kept so old config files still decode.
	// Load migrates these into Servers/ActiveServer and clears them.
	BaseURL          string  `json:"base_url,omitempty"`
	Email            string  `json:"email,omitempty"`
	Token            string  `json:"token,omitempty"`
	EncryptedPrivKey *string `json:"encrypted_privkey,omitempty"`
	PrivKeySalt      *string `json:"privkey_salt,omitempty"`

	// VaultLockMinutes is how many minutes of inactivity the TUI allows
	// before wiping the in-memory vault key and re-prompting for the master
	// password. Unset means 5 minutes; 0 disables auto-lock.
	VaultLockMinutes *int `json:"vault_lock_minutes,omitempty"`

	// AccentColor is the TUI's accent color, as a lipgloss color spec (e.g.
	// "#FF5FAF" or an ANSI-256 code like "205"). Unset means the default pink.
	AccentColor *string `json:"accent_color,omitempty"`
}

// ServerName derives a server entry's identifying name from its base URL
// and account email, as "host (email)". This keeps multiple accounts on the
// same PWDSafe instance as distinct entries. If baseURL cannot be parsed or
// has no host, baseURL itself is used in place of the host.
func ServerName(baseURL, email string) string {
	host := baseURL

	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		host = u.Host
	}

	if email == "" {
		return host
	}

	return fmt.Sprintf("%s (%s)", host, email)
}

// Active returns the currently active server, or nil if none is configured
// or ActiveServer does not match any entry.
func (c *Config) Active() *Server {
	srv, _ := c.FindServer(c.ActiveServer)

	return srv
}

// FindServer returns the server with the given name and its index in
// Servers, or (nil, -1) if not found.
func (c *Config) FindServer(name string) (*Server, int) {
	for i := range c.Servers {
		if c.Servers[i].Name == name {
			return &c.Servers[i], i
		}
	}

	return nil, -1
}

// UpsertServer replaces the server with the same Name as s, or appends s if
// no such server exists.
func (c *Config) UpsertServer(s Server) {
	if _, i := c.FindServer(s.Name); i >= 0 {
		c.Servers[i] = s

		return
	}

	c.Servers = append(c.Servers, s)
}

// RemoveServer removes the server with the given name. It returns an error
// if no such server exists.
func (c *Config) RemoveServer(name string) error {
	_, i := c.FindServer(name)
	if i < 0 {
		return fmt.Errorf("no such server %q", name)
	}

	c.Servers = append(c.Servers[:i], c.Servers[i+1:]...)

	return nil
}

// Path returns the path to the config file, creating its parent directory if needed.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(dir, "pwdsafe-cli")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return "", err
	}

	return filepath.Join(configDir, "config.json"), nil
}

// Load reads the config file. It returns an error wrapping os.ErrNotExist if
// the user has not logged in yet.
func Load() (*Config, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Servers) == 0 && cfg.BaseURL != "" {
		name := ServerName(cfg.BaseURL, cfg.Email)
		cfg.Servers = []Server{{
			Name:             name,
			BaseURL:          cfg.BaseURL,
			Email:            cfg.Email,
			Token:            cfg.Token,
			EncryptedPrivKey: cfg.EncryptedPrivKey,
			PrivKeySalt:      cfg.PrivKeySalt,
		}}
		cfg.ActiveServer = name
		cfg.BaseURL, cfg.Email, cfg.Token = "", "", ""
		cfg.EncryptedPrivKey, cfg.PrivKeySalt = nil, nil

		if err := Save(&cfg); err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

// Save writes the config file with owner-only permissions.
func Save(cfg *Config) error {
	path, err := Path()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

// Delete removes the config file. It is not an error if it does not exist.
func Delete() error {
	path, err := Path()
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}
