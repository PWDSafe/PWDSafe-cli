package tui

import (
	"crypto/rsa"
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"pwdsafe-cli/internal/api"
	"pwdsafe-cli/internal/config"
	"pwdsafe-cli/internal/vaultcrypto"
	"pwdsafe-cli/internal/vaultkey"
	"pwdsafe-cli/internal/vaultops"
)

// credentialsLoadedMsg carries the flattened, searchable list of all
// credentials across all groups, along with the raw group list (used to
// build the sidebar's group tree).
type credentialsLoadedMsg struct {
	items  []item
	groups []api.Group
}

// credentialsLoadErrMsg is sent if loading groups/credentials fails.
type credentialsLoadErrMsg struct {
	err error
}

// credentialFetchedMsg carries a single credential, including its
// ciphertext, fetched on demand.
type credentialFetchedMsg struct {
	cred *api.Credential
}

// credentialFetchErrMsg is sent if fetching a single credential fails.
type credentialFetchErrMsg struct {
	err error
}

// decryptResultMsg is the result of deriving the vault key (if needed) and
// decrypting a credential's password. vaultKey/privKey are non-nil only
// when they were freshly derived in this call, so Update can cache them.
type decryptResultMsg struct {
	vaultKey  []byte
	privKey   *rsa.PrivateKey
	plaintext string
	err       error
}

// credentialCreatedMsg is sent when a new credential has been created.
type credentialCreatedMsg struct {
	summary *api.CredentialSummary
}

// credentialCreateErrMsg is sent if creating a new credential fails.
type credentialCreateErrMsg struct {
	err error
}

// groupCreatedMsg is sent when a new group has been created.
type groupCreatedMsg struct {
	group *api.Group
}

// groupCreateErrMsg is sent if creating a new group fails.
type groupCreateErrMsg struct {
	err error
}

// credentialMovedMsg is sent when a credential has been moved to a new
// group.
type credentialMovedMsg struct {
	summary *api.CredentialSummary
}

// credentialMoveErrMsg is sent if moving a credential fails.
type credentialMoveErrMsg struct {
	err error
}

// copyTickMsg drives the one-second countdown that auto-clears the clipboard
// after a password copy. gen guards against ticks from a superseded copy.
type copyTickMsg struct {
	gen int
}

// statusExpireMsg clears a transient status message. gen guards against
// expiring a newer message.
type statusExpireMsg struct {
	gen int
}

// lockTickMsg drives the periodic inactivity check for vault auto-lock.
type lockTickMsg struct{}

// serverLoginResultMsg is the result of loginServerCmd. Exactly one of err,
// needs2FA, or server is set on success/failure.
type serverLoginResultMsg struct {
	server   *config.Server
	needs2FA bool
	err      error
}

// statusExpireAfter is how long transient status messages stay visible.
const statusExpireAfter = 5 * time.Second

// lockCheckInterval is how often vault auto-lock inactivity is checked.
const lockCheckInterval = 30 * time.Second

func copyTickCmd(gen int) tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return copyTickMsg{gen: gen} })
}

func statusExpireCmd(gen int) tea.Cmd {
	return tea.Tick(statusExpireAfter, func(time.Time) tea.Msg { return statusExpireMsg{gen: gen} })
}

func lockTickCmd() tea.Cmd {
	return tea.Tick(lockCheckInterval, func(time.Time) tea.Msg { return lockTickMsg{} })
}

// createCredentialCmd encrypts password for every member of groupID and
// creates a new credential.
func createCredentialCmd(client *api.Client, groupID int, name, url, username, password, notes string) tea.Cmd {
	return func() tea.Msg {
		encrypted, err := vaultops.EncryptForGroup(client, groupID, password)
		if err != nil {
			return credentialCreateErrMsg{err: err}
		}

		req := api.CreateCredentialRequest{
			Name:      name,
			Url:       url,
			Username:  username,
			Encrypted: encrypted,
		}

		if notes != "" {
			req.Notes = &notes
		}

		summary, err := client.CreateCredential(groupID, req)
		if err != nil {
			return credentialCreateErrMsg{err: err}
		}

		return credentialCreatedMsg{summary: summary}
	}
}

// createGroupCmd creates a new group, optionally as a sub-group of
// parentID.
func createGroupCmd(client *api.Client, name string, parentID *int) tea.Cmd {
	return func() tea.Msg {
		group, err := client.CreateGroup(api.CreateGroupRequest{Name: name, ParentID: parentID})
		if err != nil {
			return groupCreateErrMsg{err: err}
		}

		return groupCreatedMsg{group: group}
	}
}

// moveCredentialCmd encrypts plaintext for every member of groupID and
// moves the credential into that group.
func moveCredentialCmd(client *api.Client, credentialID, groupID int, plaintext string) tea.Cmd {
	return func() tea.Msg {
		encrypted, err := vaultops.EncryptForGroup(client, groupID, plaintext)
		if err != nil {
			return credentialMoveErrMsg{err: err}
		}

		summary, err := client.MoveCredential(credentialID, api.MoveCredentialRequest{
			GroupID:   groupID,
			Encrypted: encrypted,
		})
		if err != nil {
			return credentialMoveErrMsg{err: err}
		}

		return credentialMovedMsg{summary: summary}
	}
}

// loadCredentialsCmd fetches all groups and, for each, its credentials,
// flattening the result into a single searchable list.
func loadCredentialsCmd(client *api.Client) tea.Cmd {
	return func() tea.Msg {
		groups, err := client.Groups()
		if err != nil {
			return credentialsLoadErrMsg{err: err}
		}

		var items []item

		for _, g := range groups {
			creds, err := client.GroupCredentials(g.ID)
			if err != nil {
				return credentialsLoadErrMsg{err: err}
			}

			groupName := g.Name
			if g.IsPrimary {
				groupName = "Private"
			}

			for _, c := range creds {
				items = append(items, item{
					credID:    c.ID,
					name:      c.Name,
					url:       c.Url,
					username:  c.Username,
					notes:     c.Notes,
					groupName: groupName,
					groupID:   g.ID,
				})
			}
		}

		return credentialsLoadedMsg{items: items, groups: groups}
	}
}

// fetchCredentialCmd fetches a single credential, including its ciphertext.
func fetchCredentialCmd(client *api.Client, id int) tea.Cmd {
	return func() tea.Msg {
		cred, err := client.Credential(id)
		if err != nil {
			return credentialFetchErrMsg{err: err}
		}

		return credentialFetchedMsg{cred: cred}
	}
}

// decryptCmd derives the vault key and decrypts the account private key if
// cachedPrivKey is nil, then decrypts cred's password. PBKDF2 (600k
// iterations) and RSA-OAEP can take noticeable time, so this runs as a
// tea.Cmd off the UI goroutine.
func decryptCmd(srv *config.Server, cachedPrivKey *rsa.PrivateKey, password string, cred *api.Credential) tea.Cmd {
	return func() tea.Msg {
		privKey := cachedPrivKey

		var newVaultKey []byte

		var newPrivKey *rsa.PrivateKey

		if privKey == nil {
			vaultKey, err := vaultkey.DeriveVaultKey(password, *srv.PrivKeySalt)
			if err != nil {
				return decryptResultMsg{err: fmt.Errorf("deriving vault key: %w", err)}
			}

			pk, err := vaultcrypto.DecryptPrivateKey(*srv.EncryptedPrivKey, vaultKey)
			if err != nil {
				return decryptResultMsg{err: fmt.Errorf("decrypting private key: %w", err)}
			}

			privKey = pk
			newVaultKey = vaultKey
			newPrivKey = pk
		}

		plaintext, err := vaultcrypto.DecryptCredentialData(cred.Data, privKey)
		if err != nil {
			return decryptResultMsg{vaultKey: newVaultKey, privKey: newPrivKey, err: err}
		}

		return decryptResultMsg{vaultKey: newVaultKey, privKey: newPrivKey, plaintext: plaintext}
	}
}

// loginServerCmd authenticates against baseURL with email/password (and
// optionally a TOTP code), mirroring the CLI login flow. It returns a
// serverLoginResultMsg carrying either an error, a 2FA prompt, or the new
// server entry on success.
func loginServerCmd(baseURL, email, password, totpCode string) tea.Cmd {
	return func() tea.Msg {
		client := api.New(baseURL, "")

		preflight, err := client.Preflight(email)
		if err != nil {
			return serverLoginResultMsg{err: fmt.Errorf("preflight failed: %w", err)}
		}

		loginPassword := password

		switch {
		case preflight.SeparateVaultPassword && preflight.LoginSalt != nil && *preflight.LoginSalt != "":
			loginPassword, err = vaultkey.DeriveLoginHashIndependent(password, *preflight.LoginSalt)
		case preflight.UsesLoginHash:
			loginPassword, err = vaultkey.DeriveLoginHash(password, preflight.Salt)
		}

		if err != nil {
			return serverLoginResultMsg{err: fmt.Errorf("deriving login hash: %w", err)}
		}

		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown-host"
		}

		req := api.LoginRequest{
			Email:      email,
			Password:   loginPassword,
			DeviceName: "TUI on " + hostname,
			TOTPCode:   totpCode,
		}

		resp, needs2FA, err := client.Login(req)
		if err != nil {
			return serverLoginResultMsg{err: fmt.Errorf("login failed: %w", err)}
		}

		if needs2FA {
			return serverLoginResultMsg{needs2FA: true}
		}

		return serverLoginResultMsg{server: &config.Server{
			Name:             config.ServerName(baseURL, email),
			BaseURL:          baseURL,
			Email:            email,
			Token:            resp.Token,
			EncryptedPrivKey: resp.VaultData.EncryptedPrivkey,
			PrivKeySalt:      resp.VaultData.Salt,
		}}
	}
}
