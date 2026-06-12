// Command pwdsafe-cli is a minimal CLI client for PWDSafe. v1 supports
// logging in (storing a Sanctum API token) and listing credential metadata
// (site/username/group) without decrypting anything.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"pwdsafe-cli/internal/api"
	"pwdsafe-cli/internal/clipboard"
	"pwdsafe-cli/internal/config"
	"pwdsafe-cli/internal/tui"
	"pwdsafe-cli/internal/vaultcrypto"
	"pwdsafe-cli/internal/vaultkey"
	"pwdsafe-cli/internal/vaultops"
)

func main() {
	var err error

	if len(os.Args) < 2 {
		err = cmdTUI()
	} else {
		switch os.Args[1] {
		case "login":
			err = cmdLogin(os.Args[2:])
		case "logout":
			err = cmdLogout()
		case "list":
			err = cmdList(os.Args[2:])
		case "groups":
			err = cmdGroups(os.Args[2:])
		case "add":
			err = cmdAdd(os.Args[2:])
		case "move":
			err = cmdMove(os.Args[2:])
		case "show":
			err = cmdShow(os.Args[2:])
		case "devices":
			err = cmdDevices()
		case "servers":
			err = cmdServers(os.Args[2:])
		case "tui":
			err = cmdTUI()
		case "-h", "--help", "help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
			usage()
			os.Exit(1)
		}
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `pwdsafe-cli - minimal PWDSafe CLI client

Usage:
  pwdsafe-cli                              launch the interactive TUI
  pwdsafe-cli tui                          launch the interactive TUI
  pwdsafe-cli login [--url <url>] [--email <email>]
  pwdsafe-cli groups
  pwdsafe-cli groups create <name> [--parent <group-id>]
  pwdsafe-cli add <group-id>
  pwdsafe-cli move <credential-id> <group-id>
  pwdsafe-cli list [group-id]
  pwdsafe-cli show <credential-id> [--copy]
  pwdsafe-cli devices
  pwdsafe-cli servers                      list configured servers
  pwdsafe-cli servers use <name>           switch the active server
  pwdsafe-cli servers remove <name>        remove a saved server
  pwdsafe-cli logout

If --url/--email are omitted, login will prompt for them interactively,
pre-filled with the previously saved values where available.`)
}

// cmdTUI launches the interactive terminal UI for searching, viewing, and
// copying credentials.
func cmdTUI() error {
	cfg, err := config.Load()
	if err != nil {
		fmt.Println("Not logged in. Run `pwdsafe-cli login` to get started.")
		return nil
	}

	srv := cfg.Active()
	if srv == nil || srv.Token == "" {
		fmt.Println("Not logged in. Run `pwdsafe-cli login` to get started.")
		return nil
	}

	if srv.EncryptedPrivKey == nil || srv.PrivKeySalt == nil {
		fmt.Println("Vault key data missing from config, run `pwdsafe-cli login` again.")
		return nil
	}

	p := tea.NewProgram(tui.New(cfg), tea.WithAltScreen())
	_, err = p.Run()

	return err
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	baseURL := fs.String("url", "", "PWDSafe base URL, e.g. https://pwdsafe.example.com")
	email := fs.String("email", "", "Account email")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Best-effort: pre-fill prompts with previously saved values, e.g. when
	// re-logging in after a token expired. Ignore the error if there is no
	// saved config yet.
	existing, _ := config.Load()

	var existingActive *config.Server
	if existing != nil {
		existingActive = existing.Active()
	}

	if *baseURL == "" {
		defaultURL := ""
		if existingActive != nil {
			defaultURL = existingActive.BaseURL
		}

		var err error

		*baseURL, err = readLineDefault("Server URL", defaultURL)
		if err != nil {
			return err
		}
	}

	if *baseURL == "" {
		return fmt.Errorf("server URL is required")
	}

	if *email == "" {
		defaultEmail := ""
		if existingActive != nil {
			defaultEmail = existingActive.Email
		}

		var err error

		*email, err = readLineDefault("Email", defaultEmail)
		if err != nil {
			return err
		}
	}

	if *email == "" {
		return fmt.Errorf("email is required")
	}

	client := api.New(*baseURL, "")

	preflight, err := client.Preflight(*email)
	if err != nil {
		return fmt.Errorf("preflight failed: %w", err)
	}

	password, err := readPassword("Password: ")
	if err != nil {
		return err
	}

	loginPassword := password

	switch {
	case preflight.SeparateVaultPassword && preflight.LoginSalt != nil && *preflight.LoginSalt != "":
		loginPassword, err = vaultkey.DeriveLoginHashIndependent(password, *preflight.LoginSalt)
	case preflight.UsesLoginHash:
		loginPassword, err = vaultkey.DeriveLoginHash(password, preflight.Salt)
	}

	if err != nil {
		return fmt.Errorf("deriving login hash: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	req := api.LoginRequest{
		Email:      *email,
		Password:   loginPassword,
		DeviceName: "CLI on " + hostname,
	}

	resp, needs2FA, err := client.Login(req)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	if needs2FA {
		req.TOTPCode, err = readLine("Two-factor code: ")
		if err != nil {
			return err
		}

		resp, needs2FA, err = client.Login(req)
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}

		if needs2FA {
			return fmt.Errorf("invalid two-factor code")
		}
	}

	cfg := existing
	if cfg == nil {
		cfg = &config.Config{}
	}

	name := config.ServerName(*baseURL, *email)

	cfg.UpsertServer(config.Server{
		Name:             name,
		BaseURL:          *baseURL,
		Email:            *email,
		Token:            resp.Token,
		EncryptedPrivKey: resp.VaultData.EncryptedPrivkey,
		PrivKeySalt:      resp.VaultData.Salt,
	})
	cfg.ActiveServer = name

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Println("Logged in as", resp.User.Email)

	return nil
}

func cmdLogout() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in (%w)", err)
	}

	srv := cfg.Active()
	if srv == nil {
		return fmt.Errorf("not logged in")
	}

	client := api.New(srv.BaseURL, srv.Token)
	if err := client.Logout(); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	if err := cfg.RemoveServer(srv.Name); err != nil {
		return err
	}

	if len(cfg.Servers) == 0 {
		if err := config.Delete(); err != nil {
			return fmt.Errorf("removing config: %w", err)
		}

		fmt.Println("Logged out")

		return nil
	}

	cfg.ActiveServer = cfg.Servers[0].Name

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Printf("Logged out of %s. Active server is now %s.\n", srv.Name, cfg.ActiveServer)

	return nil
}

// activeServer loads the config and returns its active server, or an error
// if not logged in to any server.
func activeServer(cfg *config.Config) (*config.Server, error) {
	srv := cfg.Active()
	if srv == nil {
		return nil, fmt.Errorf("not logged in, run `pwdsafe-cli login` first")
	}

	return srv, nil
}

func cmdList(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	srv, err := activeServer(cfg)
	if err != nil {
		return err
	}

	client := api.New(srv.BaseURL, srv.Token)

	groups, err := client.Groups()
	if err != nil {
		return fmt.Errorf("listing groups: %w", err)
	}

	if len(args) > 0 {
		var groupID int
		if _, err := fmt.Sscanf(args[0], "%d", &groupID); err != nil {
			return fmt.Errorf("invalid group id %q", args[0])
		}

		filtered := groups[:0]

		for _, g := range groups {
			if g.ID == groupID {
				filtered = append(filtered, g)
			}
		}

		groups = filtered

		if len(groups) == 0 {
			return fmt.Errorf("group %d not found or not accessible", groupID)
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tGROUP\tSITE\tUSERNAME")

	for _, group := range groups {
		creds, err := client.GroupCredentials(group.ID)
		if err != nil {
			return fmt.Errorf("listing credentials for group %q: %w", group.Name, err)
		}

		for _, c := range creds {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", c.ID, group.Name, c.Site, c.Username)
		}
	}

	return w.Flush()
}

func cmdGroups(args []string) error {
	if len(args) > 0 && args[0] == "create" {
		return cmdGroupsCreate(args[1:])
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	srv, err := activeServer(cfg)
	if err != nil {
		return err
	}

	client := api.New(srv.BaseURL, srv.Token)

	groups, err := client.Groups()
	if err != nil {
		return fmt.Errorf("listing groups: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tCREDENTIALS")

	for _, g := range groups {
		creds, err := client.GroupCredentials(g.ID)
		if err != nil {
			return fmt.Errorf("listing credentials for group %q: %w", g.Name, err)
		}

		fmt.Fprintf(w, "%d\t%s\t%d\n", g.ID, g.Name, len(creds))
	}

	return w.Flush()
}

func cmdGroupsCreate(args []string) error {
	fs := flag.NewFlagSet("groups create", flag.ExitOnError)
	parentID := fs.Int("parent", 0, "ID of the parent group (omit for a top-level group)")

	// flag stops parsing at the first non-flag argument, so reorder flags
	// before positional args to allow `groups create <name> --parent <id>`
	// as well as `groups create --parent <id> <name>`.
	var flagArgs, positional []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)

			if !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positional = append(positional, a)
		}
	}

	if err := fs.Parse(append(flagArgs, positional...)); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pwdsafe-cli groups create <name> [--parent <group-id>]")
	}

	name := fs.Arg(0)

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	srv, err := activeServer(cfg)
	if err != nil {
		return err
	}

	client := api.New(srv.BaseURL, srv.Token)

	req := api.CreateGroupRequest{Name: name}
	if *parentID != 0 {
		req.ParentID = parentID
	}

	group, err := client.CreateGroup(req)
	if err != nil {
		return fmt.Errorf("creating group: %w", err)
	}

	fmt.Printf("Created group %d (%s)\n", group.ID, group.Name)

	return nil
}

func cmdAdd(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: pwdsafe-cli add <group-id>")
	}

	var groupID int
	if _, err := fmt.Sscanf(args[0], "%d", &groupID); err != nil {
		return fmt.Errorf("invalid group id %q", args[0])
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	srv, err := activeServer(cfg)
	if err != nil {
		return err
	}

	client := api.New(srv.BaseURL, srv.Token)

	site, err := readLine("Site: ")
	if err != nil {
		return err
	}

	username, err := readLine("Username: ")
	if err != nil {
		return err
	}

	password, err := readPassword("Password: ")
	if err != nil {
		return err
	}

	notes, err := readLine("Notes (optional): ")
	if err != nil {
		return err
	}

	encrypted, err := vaultops.EncryptForGroup(client, groupID, password)
	if err != nil {
		return fmt.Errorf("encrypting credential: %w", err)
	}

	req := api.CreateCredentialRequest{
		Site:      site,
		Username:  username,
		Encrypted: encrypted,
	}

	if notes != "" {
		req.Notes = &notes
	}

	cred, err := client.CreateCredential(groupID, req)
	if err != nil {
		return fmt.Errorf("creating credential: %w", err)
	}

	fmt.Printf("Created credential %d (%s / %s)\n", cred.ID, cred.Site, cred.Username)

	return nil
}

func cmdMove(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: pwdsafe-cli move <credential-id> <group-id>")
	}

	var credentialID int
	if _, err := fmt.Sscanf(args[0], "%d", &credentialID); err != nil {
		return fmt.Errorf("invalid credential id %q", args[0])
	}

	var groupID int
	if _, err := fmt.Sscanf(args[1], "%d", &groupID); err != nil {
		return fmt.Errorf("invalid group id %q", args[1])
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	srv, err := activeServer(cfg)
	if err != nil {
		return err
	}

	if srv.EncryptedPrivKey == nil || srv.PrivKeySalt == nil {
		return fmt.Errorf("vault key data missing from config, run `pwdsafe-cli login` again")
	}

	client := api.New(srv.BaseURL, srv.Token)

	cred, err := client.Credential(credentialID)
	if err != nil {
		return fmt.Errorf("fetching credential: %w", err)
	}

	password, err := readPassword("Master password: ")
	if err != nil {
		return err
	}

	vaultKey, err := vaultkey.DeriveVaultKey(password, *srv.PrivKeySalt)
	if err != nil {
		return fmt.Errorf("deriving vault key: %w", err)
	}

	privKey, err := vaultcrypto.DecryptPrivateKey(*srv.EncryptedPrivKey, vaultKey)
	if err != nil {
		return fmt.Errorf("decrypting private key: %w", err)
	}

	credPassword, err := vaultcrypto.DecryptCredentialData(cred.Data, privKey)
	if err != nil {
		return fmt.Errorf("decrypting credential: %w", err)
	}

	encrypted, err := vaultops.EncryptForGroup(client, groupID, credPassword)
	if err != nil {
		return fmt.Errorf("encrypting credential for destination group: %w", err)
	}

	moved, err := client.MoveCredential(credentialID, api.MoveCredentialRequest{
		GroupID:   groupID,
		Encrypted: encrypted,
	})
	if err != nil {
		return fmt.Errorf("moving credential: %w", err)
	}

	groupName := fmt.Sprintf("group %d", groupID)
	if moved.Group != nil {
		groupName = moved.Group.Name
	}

	fmt.Printf("Moved credential %d (%s / %s) to %s\n", moved.ID, moved.Site, moved.Username, groupName)

	return nil
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	copyToClipboard := fs.Bool("copy", false, "copy the password to the clipboard instead of printing it")

	// flag stops parsing at the first non-flag argument, so reorder flags
	// before positional args to allow `show <id> --copy` as well as
	// `show --copy <id>`.
	var flagArgs, positional []string

	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
		} else {
			positional = append(positional, a)
		}
	}

	if err := fs.Parse(append(flagArgs, positional...)); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: pwdsafe-cli show <credential-id> [--copy]")
	}

	var credentialID int
	if _, err := fmt.Sscanf(fs.Arg(0), "%d", &credentialID); err != nil {
		return fmt.Errorf("invalid credential id %q", fs.Arg(0))
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	srv, err := activeServer(cfg)
	if err != nil {
		return err
	}

	if srv.EncryptedPrivKey == nil || srv.PrivKeySalt == nil {
		return fmt.Errorf("vault key data missing from config, run `pwdsafe-cli login` again")
	}

	client := api.New(srv.BaseURL, srv.Token)

	cred, err := client.Credential(credentialID)
	if err != nil {
		return fmt.Errorf("fetching credential: %w", err)
	}

	password, err := readPassword("Master password: ")
	if err != nil {
		return err
	}

	vaultKey, err := vaultkey.DeriveVaultKey(password, *srv.PrivKeySalt)
	if err != nil {
		return fmt.Errorf("deriving vault key: %w", err)
	}

	privKey, err := vaultcrypto.DecryptPrivateKey(*srv.EncryptedPrivKey, vaultKey)
	if err != nil {
		return fmt.Errorf("decrypting private key: %w", err)
	}

	credPassword, err := vaultcrypto.DecryptCredentialData(cred.Data, privKey)
	if err != nil {
		return fmt.Errorf("decrypting credential: %w", err)
	}

	if *copyToClipboard {
		if err := clipboard.Copy(credPassword); err != nil {
			return fmt.Errorf("copying to clipboard: %w", err)
		}

		fmt.Printf("Password for %s (%s) copied to clipboard\n", cred.Site, cred.Username)

		return nil
	}

	fmt.Printf("Site:     %s\n", cred.Site)
	fmt.Printf("Username: %s\n", cred.Username)
	fmt.Printf("Password: %s\n", credPassword)

	return nil
}

func cmdDevices() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	srv, err := activeServer(cfg)
	if err != nil {
		return err
	}

	client := api.New(srv.BaseURL, srv.Token)

	devices, err := client.Devices()
	if err != nil {
		return fmt.Errorf("listing devices: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tLAST USED\tCURRENT")

	for _, d := range devices {
		lastUsed := "never"
		if d.LastUsedAt != nil {
			lastUsed = *d.LastUsedAt
		}

		current := ""
		if d.IsCurrent {
			current = "*"
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", d.ID, d.Name, lastUsed, current)
	}

	return w.Flush()
}

func cmdServers(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		return cmdServersList()
	}

	switch args[0] {
	case "use":
		return cmdServersUse(args[1:])
	case "remove":
		return cmdServersRemove(args[1:])
	default:
		return fmt.Errorf("usage: pwdsafe-cli servers [list|use <name>|remove <name>]")
	}
}

func cmdServersList() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	if len(cfg.Servers) == 0 {
		fmt.Println("No servers configured. Run `pwdsafe-cli login` to add one.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tURL\tEMAIL\tACTIVE")

	for _, srv := range cfg.Servers {
		active := ""
		if srv.Name == cfg.ActiveServer {
			active = "*"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", srv.Name, srv.BaseURL, srv.Email, active)
	}

	return w.Flush()
}

func cmdServersUse(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: pwdsafe-cli servers use <name>")
	}

	name := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	if _, idx := cfg.FindServer(name); idx < 0 {
		return fmt.Errorf("unknown server %q", name)
	}

	cfg.ActiveServer = name

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Printf("Switched active server to %s\n", name)

	return nil
}

func cmdServersRemove(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: pwdsafe-cli servers remove <name>")
	}

	name := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("not logged in, run `pwdsafe-cli login` first (%w)", err)
	}

	if name == cfg.ActiveServer {
		return fmt.Errorf("cannot remove the active server %q, switch first with `pwdsafe-cli servers use <other>`", name)
	}

	if err := cfg.RemoveServer(name); err != nil {
		return err
	}

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	fmt.Printf("Removed server %s\n", name)

	return nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))

	fmt.Fprintln(os.Stderr)

	if err != nil {
		return "", err
	}

	return string(bytePassword), nil
}

// readLineDefault prompts for a line of input, showing def as the default
// value. If the user enters nothing, def is returned.
func readLineDefault(prompt, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
	}

	reader := bufio.NewReader(os.Stdin)

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	line = trimNewline(line)
	if line == "" {
		return def, nil
	}

	return line, nil
}

func readLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	reader := bufio.NewReader(os.Stdin)

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return trimNewline(line), nil
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}

	return s
}
