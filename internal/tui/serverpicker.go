package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"pwdsafe-cli/internal/api"
	"pwdsafe-cli/internal/config"
)

// openServerPicker switches to the server picker view, placing the cursor on
// the currently active server.
func (m Model) openServerPicker() (tea.Model, tea.Cmd) {
	m.serverPickerCursor = 0

	for i, srv := range m.cfg.Servers {
		if srv.Name == m.cfg.ActiveServer {
			m.serverPickerCursor = i

			break
		}
	}

	m.state = stateServerPicker
	m.statusMsg = ""

	return m, nil
}

func (m Model) handleServerPickerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.state = stateBrowse
		m.statusMsg = ""

		return m, nil

	case "up", "k":
		if m.serverPickerCursor > 0 {
			m.serverPickerCursor--
		}

		return m, nil

	case "down", "j":
		if m.serverPickerCursor < len(m.cfg.Servers) {
			m.serverPickerCursor++
		}

		return m, nil

	case "enter":
		if m.serverPickerCursor == len(m.cfg.Servers) {
			return m.openAddServerForm()
		}

		return m.switchServer(m.serverPickerCursor)
	}

	return m, nil
}

// openAddServerForm resets and focuses the add-server form, switching to
// stateAddServerForm.
func (m Model) openAddServerForm() (tea.Model, tea.Cmd) {
	for i := range m.addServerForm {
		m.addServerForm[i].Reset()
		m.addServerForm[i].Blur()
	}

	m.addServerFocus = addServerFieldURL
	m.addServerForm[m.addServerFocus].Focus()

	m.state = stateAddServerForm
	m.statusMsg = ""

	return m, textinput.Blink
}

// handleAddServerFormKey processes key presses while the add-server form is
// shown.
func (m Model) handleAddServerFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		for i := range m.addServerForm {
			m.addServerForm[i].Reset()
			m.addServerForm[i].Blur()
		}

		m.state = stateServerPicker
		m.statusMsg = ""

		return m, nil

	case "tab", "down":
		m.addServerForm[m.addServerFocus].Blur()
		m.addServerFocus = (m.addServerFocus + 1) % numAddServerFields
		m.addServerForm[m.addServerFocus].Focus()

		return m, textinput.Blink

	case "shift+tab", "up":
		m.addServerForm[m.addServerFocus].Blur()
		m.addServerFocus = (m.addServerFocus - 1 + numAddServerFields) % numAddServerFields
		m.addServerForm[m.addServerFocus].Focus()

		return m, textinput.Blink

	case "enter":
		url := strings.TrimSpace(m.addServerForm[addServerFieldURL].Value())
		email := strings.TrimSpace(m.addServerForm[addServerFieldEmail].Value())
		password := m.addServerForm[addServerFieldPassword].Value()

		if url == "" || email == "" || password == "" {
			return m, m.setStatus("Server URL, email, and password are required.")
		}

		m.pendingServerURL = url
		m.pendingServerEmail = email
		m.pendingServerPassword = password

		return m, tea.Batch(m.setBusy("Logging in..."), loginServerCmd(url, email, password, ""))
	}

	var cmd tea.Cmd

	m.addServerForm[m.addServerFocus], cmd = m.addServerForm[m.addServerFocus].Update(msg)

	return m, cmd
}

// handleAddServer2FAKey processes key presses while the add-server 2FA
// prompt is shown.
func (m Model) handleAddServer2FAKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.addServer2FAInput.Reset()
		m.state = stateAddServerForm
		m.statusMsg = ""

		return m, nil

	case "enter":
		code := strings.TrimSpace(m.addServer2FAInput.Value())
		if code == "" {
			return m, m.setStatus("Two-factor code is required.")
		}

		return m, tea.Batch(m.setBusy("Logging in..."), loginServerCmd(m.pendingServerURL, m.pendingServerEmail, m.pendingServerPassword, code))
	}

	var cmd tea.Cmd

	m.addServer2FAInput, cmd = m.addServer2FAInput.Update(msg)

	return m, cmd
}

// handleServerLoginResult processes the outcome of loginServerCmd: an error
// (stay on the current form with a status message), a 2FA prompt, or a new
// server entry to add and switch to.
func (m Model) handleServerLoginResult(msg serverLoginResultMsg) (tea.Model, tea.Cmd) {
	m.busy = false

	if msg.err != nil {
		return m, m.setStatus(msg.err.Error())
	}

	if msg.needs2FA {
		m.state = stateAddServer2FA
		m.addServer2FAInput.Reset()
		m.addServer2FAInput.Focus()
		m.statusMsg = ""

		return m, textinput.Blink
	}

	m.vault.wipe()
	m.cancelCopyCountdown()

	m.cfg.UpsertServer(*msg.server)
	m.cfg.ActiveServer = msg.server.Name
	m.client = api.New(msg.server.BaseURL, msg.server.Token)

	m.plaintext = ""
	m.revealed = false
	m.revealedCredID = 0
	m.credential = nil
	m.selected = item{}
	m.allItems = nil
	m.groups = nil
	m.pendingServerURL = ""
	m.pendingServerEmail = ""
	m.pendingServerPassword = ""
	m.statusMsg = ""

	if err := config.Save(m.cfg); err != nil {
		m.state = stateBrowse

		return m, m.setStatus("Added server but failed to save config: " + err.Error())
	}

	m.state = stateLoading

	return m, tea.Batch(loadCredentialsCmd(m.client), m.spinner.Tick)
}

// switchServer makes the server at idx the active one, wiping the current
// vault session and reloading credentials from it. If the target server
// lacks usable credentials, it shows a status message instead of switching.
func (m Model) switchServer(idx int) (tea.Model, tea.Cmd) {
	if idx < 0 || idx >= len(m.cfg.Servers) {
		return m, nil
	}

	srv := &m.cfg.Servers[idx]

	if srv.Name == m.cfg.ActiveServer {
		m.state = stateBrowse
		m.statusMsg = ""

		return m, nil
	}

	if srv.Token == "" || srv.EncryptedPrivKey == nil || srv.PrivKeySalt == nil {
		return m, m.setStatus(fmt.Sprintf("Server %s needs `pwdsafe-cli login` to refresh credentials.", srv.Name))
	}

	m.vault.wipe()
	m.cancelCopyCountdown()

	m.cfg.ActiveServer = srv.Name
	m.client = api.New(srv.BaseURL, srv.Token)

	m.plaintext = ""
	m.revealed = false
	m.revealedCredID = 0
	m.credential = nil
	m.selected = item{}
	m.allItems = nil
	m.groups = nil
	m.statusMsg = ""

	if err := config.Save(m.cfg); err != nil {
		return m, m.setStatus("Switched server but failed to save config: " + err.Error())
	}

	m.state = stateLoading

	return m, tea.Batch(loadCredentialsCmd(m.client), m.spinner.Tick)
}

// renderServerPicker renders the list of configured servers, highlighting
// the active and currently-selected entries.
func renderServerPicker(m Model) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Servers") + "\n\n")

	for i, srv := range m.cfg.Servers {
		cursor := "  "
		if i == m.serverPickerCursor {
			cursor = "> "
		}

		label := srv.Name
		if srv.Name == m.cfg.ActiveServer {
			label = styleSwatchSelected.Render(label + " (active)")
		}

		fmt.Fprintf(&b, "%s%s\n", cursor, label)
	}

	addCursor := "  "
	if m.serverPickerCursor == len(m.cfg.Servers) {
		addCursor = "> "
	}

	fmt.Fprintf(&b, "%s%s\n", addCursor, styleHelp.Render("+ Add server"))

	if m.statusMsg != "" {
		b.WriteString("\n" + styleStatus.Render(m.statusMsg) + "\n")
	}

	b.WriteString("\n" + styleHelp.Render("↑/↓ select · enter switch/add · esc back"))

	return b.String()
}

// renderAddServerForm renders the modal form for adding a new server, with
// fields for URL, email, and password.
func renderAddServerForm(fields []textinput.Model, statusMsg string) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Add server") + "\n\n")

	labels := []string{"URL:     ", "Email:   ", "Password:"}

	for i, f := range fields {
		fmt.Fprintf(&b, "%s %s\n", styleLabel.Render(labels[i]), f.View())
	}

	if statusMsg != "" {
		b.WriteString("\n" + styleStatus.Render(statusMsg) + "\n")
	}

	b.WriteString("\n" + styleHelp.Render("tab/shift+tab next/prev field · enter log in · esc cancel"))

	return b.String()
}

// renderAddServer2FA renders the two-factor code prompt shown when adding a
// new server whose account requires TOTP.
func renderAddServer2FA(input textinput.Model, statusMsg string) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Two-factor code") + "\n\n")
	b.WriteString("Enter the 6-digit code from your authenticator app.\n\n")
	b.WriteString(input.View() + "\n")

	if statusMsg != "" {
		b.WriteString("\n" + styleStatus.Render(statusMsg) + "\n")
	}

	b.WriteString("\n" + styleHelp.Render("enter confirm · esc back"))

	return b.String()
}
