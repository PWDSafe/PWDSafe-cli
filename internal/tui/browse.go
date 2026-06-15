package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"pwdsafe-cli/internal/clipboard"
	"pwdsafe-cli/internal/config"
)

const (
	sidebarWidth       = 32
	detailWidth        = 36
	narrowThreshold    = 80
	verySmallThreshold = 50

	maskedPassword = "••••••••••"
)

// computePaneWidths returns the outer (border-inclusive) widths for the
// sidebar, table, and detail panes, plus the shared content height
// available to each pane, given the terminal size. Below narrowThreshold
// the detail pane is hidden; below verySmallThreshold the sidebar is hidden
// too (the caller should then force showAll).
func computePaneWidths(width, height int) (sidebarW, tableW, detailW, paneH int) {
	paneH = height - 2 // reserve one line for the header and one for the bottom status/help bar
	if paneH < 1 {
		paneH = 1
	}

	switch {
	case width < verySmallThreshold:
		return 0, width, 0, paneH
	case width < narrowThreshold:
		sidebarW = sidebarWidth
		tableW = width - sidebarW

		return sidebarW, tableW, 0, paneH
	default:
		sidebarW = sidebarWidth
		detailW = detailWidth
		tableW = width - sidebarW - detailW

		return sidebarW, tableW, detailW, paneH
	}
}

// allocateTableColumns distributes the available content width across the
// credential table's columns. The Group column is given zero width (and so
// is not rendered by bubbles/table) when a single group is selected, since
// it would be redundant with the sidebar selection.
func allocateTableColumns(width int, showGroupCol bool) []table.Column {
	const cellPadding = 2 // bubbles/table cell style adds 1 column of padding per side

	numCols := 3
	if showGroupCol {
		numCols = 4
	}

	avail := width - cellPadding*numCols
	if avail < 10 {
		avail = 10
	}

	nameW := avail * 30 / 100
	userW := avail * 25 / 100

	groupW := 0
	if showGroupCol {
		groupW = avail * 20 / 100
	}

	notesW := avail - nameW - userW - groupW

	return []table.Column{
		{Title: "Name", Width: nameW},
		{Title: "Username", Width: userW},
		{Title: "Notes", Width: notesW},
		{Title: "Group", Width: groupW},
	}
}

// visibleItems returns the credentials to show in the table given the
// current group selection and/or active text filter. The text filter is
// scoped to the currently selected group, unless "All credentials" (showAll)
// is selected, in which case it searches across all credentials.
func visibleItems(all []item, selectedGroupID int, showAll bool, filterQuery string) []item {
	var scoped []item

	if showAll {
		scoped = all
	} else {
		for _, it := range all {
			if it.groupID == selectedGroupID {
				scoped = append(scoped, it)
			}
		}
	}

	if filterQuery == "" {
		return scoped
	}

	q := strings.ToLower(filterQuery)

	var out []item

	for _, it := range scoped {
		hay := strings.ToLower(it.name + " " + it.url + " " + it.username + " " + it.notes + " " + it.groupName)
		if strings.Contains(hay, q) {
			out = append(out, it)
		}
	}

	return out
}

// toRows converts items into table rows. Always produces 4-element rows
// (Name, Username, Notes, Group) to match allocateTableColumns, which may
// give the Group column zero width.
func toRows(items []item) []table.Row {
	rows := make([]table.Row, len(items))

	for i, it := range items {
		rows[i] = table.Row{it.name, it.username, it.notes, it.groupName}
	}

	return rows
}

// refreshTable recomputes m.visibleItems and the table's columns/rows from
// the current group selection / filter query. If resetCursor is true, the
// table cursor and any reveal state are reset (used when the group
// selection or filter changes).
func (m *Model) refreshTable(resetCursor bool) {
	m.visibleItems = visibleItems(m.allItems, m.selectedGroupID, m.showAll, m.filterQuery)

	showGroupCol := m.showAll
	m.table.SetColumns(allocateTableColumns(m.table.Width(), showGroupCol))
	m.table.SetRows(toRows(m.visibleItems))

	if resetCursor {
		m.table.SetCursor(0)
		m.revealed = false
		m.revealedCredID = 0
		m.plaintext = ""
	}

	m.updateSelectedFromCursor()
}

// updateSelectedFromCursor syncs m.selected with the item under the table
// cursor.
func (m *Model) updateSelectedFromCursor() {
	if len(m.visibleItems) == 0 {
		m.selected = item{}

		return
	}

	cursor := m.table.Cursor()
	if cursor < 0 || cursor >= len(m.visibleItems) {
		cursor = 0
	}

	m.selected = m.visibleItems[cursor]
}

// ensureDecrypted fetches the highlighted credential's ciphertext (if not
// already cached) and either decrypts it directly (vault already unlocked)
// or prompts for the master password. The result arrives via
// decryptResultMsg / credentialFetchedMsg, handled according to
// m.pendingAction.
func (m Model) ensureDecrypted() (tea.Model, tea.Cmd) {
	if m.credential != nil && m.credential.ID == m.selected.credID {
		if m.vault.ready() {
			return m, tea.Batch(m.setBusy("Decrypting..."), decryptCmd(m.cfg.Active(), m.vault.privKey, "", m.credential))
		}

		m.state = statePasswordPrompt
		m.pwInput.Reset()
		m.pwInput.Focus()

		return m, textinput.Blink
	}

	return m, tea.Batch(m.setBusy("Fetching credential..."), fetchCredentialCmd(m.client, m.selected.credID))
}

// startReveal toggles the password reveal state for the highlighted row,
// decrypting it first if necessary.
func (m Model) startReveal() (tea.Model, tea.Cmd) {
	if m.selected.credID == 0 {
		return m, nil
	}

	if m.revealed && m.revealedCredID == m.selected.credID {
		m.revealed = false

		return m, nil
	}

	if m.plaintext != "" && m.revealedCredID == m.selected.credID {
		m.revealed = true

		return m, nil
	}

	m.pendingAction = actionView

	return m.ensureDecrypted()
}

// startCopy copies the highlighted row's password to the clipboard,
// decrypting it first if necessary. The displayed reveal state is
// unaffected.
func (m Model) startCopy() (tea.Model, tea.Cmd) {
	if m.selected.credID == 0 {
		return m, nil
	}

	if m.plaintext != "" && m.revealedCredID == m.selected.credID {
		if err := clipboard.Copy(m.plaintext); err != nil {
			return m, m.setStatus("Clipboard copy failed: " + err.Error())
		}

		return m, m.startCopyCountdown(m.plaintext, m.selected.name)
	}

	m.pendingAction = actionCopy

	return m.ensureDecrypted()
}

// copyUsername copies the highlighted row's username to the clipboard.
// Usernames are not encrypted, so no decryption round-trip is needed.
func (m Model) copyUsername() (tea.Model, tea.Cmd) {
	if m.selected.credID == 0 {
		return m, nil
	}

	if err := clipboard.Copy(m.selected.username); err != nil {
		return m, m.setStatus("Clipboard copy failed: " + err.Error())
	}

	// the clipboard now holds the username; a pending password auto-clear
	// would wipe it, so cancel the countdown
	m.cancelCopyCountdown()

	return m, m.setStatus(fmt.Sprintf("Copied username for %s", m.selected.name))
}

// startMove begins moving the highlighted credential to another group,
// decrypting it first if necessary.
func (m Model) startMove() (tea.Model, tea.Cmd) {
	if m.selected.credID == 0 {
		return m, nil
	}

	m.pendingAction = actionMove

	return m.ensureDecrypted()
}

// renderDetailPane renders the right-hand pane showing the highlighted
// credential's metadata, always visible, and its password, masked until
// revealed.
func renderDetailPane(it item, plaintext string, revealed bool, width, height int) string {
	if it.credID == 0 {
		return styleHelp.Render("No credential selected.")
	}

	var b strings.Builder

	b.WriteString(styleTitle.Render("Credential") + "\n\n")
	fmt.Fprintf(&b, "%s %s\n", styleLabel.Render("Name:    "), it.name)

	if it.url != "" {
		fmt.Fprintf(&b, "%s %s\n", styleLabel.Render("URL:     "), it.url)
	}

	fmt.Fprintf(&b, "%s %s\n", styleLabel.Render("Username:"), it.username)

	if it.notes != "" {
		fmt.Fprintf(&b, "%s %s\n", styleLabel.Render("Notes:   "), it.notes)
	}

	b.WriteString("\n")

	pw := maskedPassword

	pwStyle := stylePasswordMasked
	if revealed && plaintext != "" {
		pw = plaintext
		pwStyle = stylePassword
	}

	fmt.Fprintf(&b, "%s %s\n", styleLabel.Render("Password:"), pwStyle.Render(pw))

	b.WriteString("\n" + styleHelp.Render("v reveal/hide · c copy"))

	return lipgloss.NewStyle().Width(width).Height(height).Render(b.String())
}

// renderBrowse composes the 3-pane browse layout: groups sidebar,
// credentials table, and (when wide enough) the credential detail pane,
// followed by a status/help/filter line.
func renderBrowse(m Model) string {
	sidebarW, _, detailW, paneH := computePaneWidths(m.width, m.height)

	var panes []string

	if sidebarW > 0 {
		sidebarPaneStyle := styleSidebarPane
		if m.focus == focusSidebar {
			sidebarPaneStyle = styleSidebarPaneFocused
		}

		content := m.sidebar.View(m.focus == focusSidebar)
		panes = append(panes, sidebarPaneStyle.Width(max(sidebarW-4, 0)).Height(max(paneH-2, 0)).Render(content))
	}

	tablePaneStyle := styleTablePane
	if m.focus == focusTable {
		tablePaneStyle = styleTablePaneFocused
	}

	panes = append(panes, tablePaneStyle.Render(m.table.View()))

	if detailW > 0 {
		content := renderDetailPane(m.selected, m.plaintext, m.revealed, max(detailW-4, 0), max(paneH-2, 0))
		panes = append(panes, styleDetailPane.Width(max(detailW-4, 0)).Height(max(paneH-2, 0)).Render(content))
	}

	middle := lipgloss.JoinHorizontal(lipgloss.Top, panes...)

	header := lipgloss.NewStyle().MaxWidth(max(m.width, 0)).Render(styleHelp.Render("pwdsafe-cli · " + activeServerLabel(m.cfg)))

	var bottom string

	switch {
	case m.filterEditing || m.filterQuery != "":
		bottom = "/" + m.filterInput.View()
		if m.filterQuery != "" {
			bottom += styleHelp.Render("  " + countLabel(len(m.visibleItems), "match", "matches"))
		}
	case m.busy:
		bottom = m.spinner.View() + " " + styleStatus.Render(m.statusMsg)
	case m.statusMsg != "":
		bottom = styleStatus.Render(m.statusMsg)
	default:
		count := countLabel(len(m.visibleItems), "credential", "credentials")
		bottom = styleHelp.Render(count + " · tab focus · / filter · v reveal · c/u copy · a add · g group · m move · s settings · S server · ? help · q quit")
	}

	return lipgloss.JoinVertical(lipgloss.Left, header, middle, bottom)
}

// activeServerLabel returns the active server's name for display in the
// browse header, or a placeholder if none is configured.
func activeServerLabel(cfg *config.Config) string {
	if srv := cfg.Active(); srv != nil {
		return srv.Name
	}

	return "no server configured"
}

// countLabel formats n with a singular/plural noun, e.g. "1 match",
// "12 credentials".
func countLabel(n int, singular, plural string) string {
	noun := plural
	if n == 1 {
		noun = singular
	}

	return fmt.Sprintf("%d %s", n, noun)
}
