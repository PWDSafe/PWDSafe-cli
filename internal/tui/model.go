package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"pwdsafe-cli/internal/api"
	"pwdsafe-cli/internal/clipboard"
	"pwdsafe-cli/internal/config"
)

const (
	// copyClearAfter is the countdown, in seconds, before a copied password
	// is cleared from the clipboard.
	copyClearAfter = 30

	// defaultLockTimeout is how long the vault key stays in memory without
	// any keyboard activity before it is wiped (overridable via
	// config.VaultLockMinutes).
	defaultLockTimeout = 5 * time.Minute

	// modalListWidth and modalListHeight bound the size of the group-picker
	// list when shown as a modal overlay.
	modalListWidth  = 60
	modalListHeight = 16

	// modalInputWidth bounds the width of text inputs shown in modal forms
	// (add credential / create group).
	modalInputWidth = 36
)

type state int

const (
	stateLoading state = iota
	stateBrowse
	statePasswordPrompt
	stateError
	stateGroupPicker
	stateAddForm
	stateCreateGroupForm
	stateSettings
	stateServerPicker
	stateAddServerForm
	stateAddServer2FA
)

// focusArea identifies which pane of the browse view has keyboard focus.
type focusArea int

const (
	focusSidebar focusArea = iota
	focusTable
)

type action int

const (
	actionView action = iota
	actionCopy
	actionMove
)

// pickerMode distinguishes what selecting a group in stateGroupPicker
// should do: add a new credential to it, or move an existing credential
// into it.
type pickerMode int

const (
	pickerAdd pickerMode = iota
	pickerMove
)

const (
	addFieldSite = iota
	addFieldUsername
	addFieldPassword
	addFieldNotes
	numAddFields
)

const (
	addServerFieldURL = iota
	addServerFieldEmail
	addServerFieldPassword
	numAddServerFields
)

// Model is the root bubbletea model for the pwdsafe-cli TUI.
type Model struct {
	cfg    *config.Config
	client *api.Client

	state state
	err   error

	pwInput textinput.Model

	// browse view state (3-pane layout).
	groups          []api.Group
	allItems        []item
	groupTree       []groupNode
	visibleItems    []item
	sidebar         sidebarModel
	table           table.Model
	focus           focusArea
	selectedGroupID int
	showAll         bool

	filterEditing bool
	filterInput   textinput.Model
	filterQuery   string

	selected      item
	credential    *api.Credential
	pendingAction action

	vault *vaultSession

	plaintext      string
	revealed       bool
	revealedCredID int
	statusMsg      string

	// pendingStatusMsg is shown once the credential list finishes
	// reloading after a successful add.
	pendingStatusMsg string

	// statusGeneration invalidates pending statusExpireMsg ticks whenever a
	// newer status takes over the status bar.
	statusGeneration int

	// spinner is shown next to the status message while busy (an async
	// fetch/decrypt/create is in flight).
	spinner spinner.Model
	busy    bool

	// showHelp overlays the keybinding reference on the browse view.
	showHelp bool

	// clipboard auto-clear countdown after a password copy. copiedPassword
	// is kept only to verify the clipboard still holds it before clearing.
	copyCountdown  int
	copyGeneration int
	copiedPassword string
	copiedSite     string

	// lastActivity drives vault auto-lock; updated on every key press.
	lastActivity time.Time

	// group picker + add-credential form state.
	groupPicker      sidebarModel
	groupPickerTitle string
	selectedGroup    api.Group
	addForm          [numAddFields]textinput.Model
	addFocus         int
	groupPickerMode  pickerMode

	// create-group form state.
	groupNameInput   textinput.Model
	newGroupParentID *int
	newGroupParent   string

	// settings view state.
	settingsCursor      int
	settingsCustomInput textinput.Model
	settingsEditingHex  bool

	// server picker view state.
	serverPickerCursor int

	// add-server form + 2FA prompt state.
	addServerForm         [numAddServerFields]textinput.Model
	addServerFocus        int
	addServer2FAInput     textinput.Model
	pendingServerURL      string
	pendingServerEmail    string
	pendingServerPassword string

	width, height int
}

// New creates the root TUI model for the given (already authenticated)
// config.
func New(cfg *config.Config) Model {
	ti := textinput.New()
	ti.Placeholder = "master password"
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.CharLimit = 256
	ti.Width = 40

	gn := textinput.New()
	gn.Placeholder = "Group name"
	gn.CharLimit = 256
	gn.Width = 40

	fi := textinput.New()
	fi.Placeholder = "filter credentials..."
	fi.CharLimit = 256

	tbl := table.New(
		table.WithColumns(allocateTableColumns(0, true)),
		table.WithFocused(true),
	)

	if cfg.AccentColor != nil {
		SetAccentColor(*cfg.AccentColor)
	}

	tbl.SetStyles(tableStyles())

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = styleSpinner

	hi := textinput.New()
	hi.Placeholder = "#RRGGBB"
	hi.CharLimit = 7
	hi.Width = 10

	srv := cfg.Active()

	m := Model{
		cfg:                 cfg,
		client:              api.New(srv.BaseURL, srv.Token),
		state:               stateLoading,
		pwInput:             ti,
		groupNameInput:      gn,
		filterInput:         fi,
		table:               tbl,
		spinner:             sp,
		focus:               focusSidebar,
		showAll:             true,
		selectedGroupID:     0,
		vault:               &vaultSession{},
		lastActivity:        time.Now(),
		settingsCustomInput: hi,
	}

	for i := range m.addForm {
		f := textinput.New()
		f.CharLimit = 256
		f.Width = 40

		switch i {
		case addFieldSite:
			f.Placeholder = "Site"
		case addFieldUsername:
			f.Placeholder = "Username"
		case addFieldPassword:
			f.Placeholder = "Password"
			f.EchoMode = textinput.EchoPassword
			f.EchoCharacter = '•'
		case addFieldNotes:
			f.Placeholder = "Notes (optional)"
		}

		m.addForm[i] = f
	}

	for i := range m.addServerForm {
		f := textinput.New()
		f.CharLimit = 256
		f.Width = 40

		switch i {
		case addServerFieldURL:
			f.Placeholder = "https://pwdsafe.example.com"
		case addServerFieldEmail:
			f.Placeholder = "Email"
		case addServerFieldPassword:
			f.Placeholder = "Password"
			f.EchoMode = textinput.EchoPassword
			f.EchoCharacter = '•'
		}

		m.addServerForm[i] = f
	}

	tfa := textinput.New()
	tfa.Placeholder = "123456"
	tfa.CharLimit = 10
	tfa.Width = 10
	m.addServer2FAInput = tfa

	return m
}

// setGroupPickerTree populates the group picker with a hierarchical view of
// groups, ready for stateGroupPicker. currentGroupID (0 if none) and groups
// the user lacks write/admin permission on are shown but disabled.
func (m *Model) setGroupPickerTree(groups []api.Group, currentGroupID int, title string) {
	m.groupPicker.SetNodes(buildGroupPickerTree(groups, currentGroupID))
	m.groupPickerTitle = title
}

// writableGroups returns the groups the user has admin or write permission
// on.
func writableGroups(groups []api.Group) []api.Group {
	var out []api.Group

	for _, g := range groups {
		if g.Permission == "admin" || g.Permission == "write" {
			out = append(out, g)
		}
	}

	return out
}

// resetAddForm clears all add-credential form fields and focuses the first
// one.
func (m *Model) resetAddForm() {
	for i := range m.addForm {
		m.addForm[i].Reset()
		m.addForm[i].Blur()
	}

	m.addFocus = addFieldSite
	m.addForm[m.addFocus].Focus()
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(loadCredentialsCmd(m.client), m.spinner.Tick, lockTickCmd())
}

// setStatus shows a transient status message that auto-clears after
// statusExpireAfter, and ends any in-flight busy indicator.
func (m *Model) setStatus(s string) tea.Cmd {
	m.statusMsg = s
	m.busy = false
	m.statusGeneration++

	return statusExpireCmd(m.statusGeneration)
}

// setBusy shows a status message with a spinner for an async operation; the
// message persists until replaced by the operation's result.
func (m *Model) setBusy(s string) tea.Cmd {
	m.statusMsg = s
	m.busy = true
	m.statusGeneration++

	return m.spinner.Tick
}

// startCopyCountdown arms the post-copy clipboard auto-clear timer and takes
// over the status bar with a live countdown.
func (m *Model) startCopyCountdown(password, site string) tea.Cmd {
	m.copiedPassword = password
	m.copiedSite = site
	m.copyCountdown = copyClearAfter
	m.copyGeneration++
	m.statusGeneration++ // cancel any pending status expiry
	m.busy = false
	m.statusMsg = copyCountdownStatus(site, m.copyCountdown)

	return copyTickCmd(m.copyGeneration)
}

// cancelCopyCountdown stops a pending clipboard auto-clear, e.g. because the
// clipboard now holds something else.
func (m *Model) cancelCopyCountdown() {
	m.copyGeneration++
	m.copyCountdown = 0
	m.copiedPassword = ""
	m.copiedSite = ""
}

func copyCountdownStatus(site string, seconds int) string {
	return fmt.Sprintf("Copied password for %s · clearing clipboard in %ds", site, seconds)
}

// lockTimeout returns the configured vault auto-lock timeout; 0 disables
// auto-lock.
func (m Model) lockTimeout() time.Duration {
	if m.cfg.VaultLockMinutes != nil {
		return time.Duration(*m.cfg.VaultLockMinutes) * time.Minute
	}

	return defaultLockTimeout
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

		sidebarW, tableW, _, paneH := computePaneWidths(m.width, m.height)

		m.sidebar.width = max(sidebarW-6, 0)
		m.sidebar.height = max(paneH-2, 0)

		m.table.SetWidth(max(tableW-2, 0))
		m.table.SetHeight(max(paneH-2, 0))
		m.refreshTable(false)

		if sidebarW == 0 {
			m.showAll = true
			m.selectedGroupID = 0
			m.refreshTable(true)
		}

		m.groupPicker.width = max(min(modalListWidth, m.width-8)-10, 10)
		m.groupPicker.height = max(min(modalListHeight, m.height-6)-4, 1)

		inputWidth := min(modalInputWidth, max(m.width-12, 10))
		m.pwInput.Width = inputWidth
		m.groupNameInput.Width = inputWidth

		// leave room for the live match count after the filter input
		m.filterInput.Width = max(msg.Width-24, 10)

		for i := range m.addForm {
			m.addForm[i].Width = inputWidth
		}

		for i := range m.addServerForm {
			m.addServerForm[i].Width = inputWidth
		}

		return m, nil

	case credentialsLoadedMsg:
		m.state = stateBrowse
		m.busy = false
		m.groups = msg.groups
		m.allItems = msg.items

		prevSelectedID := m.selectedGroupID
		if len(m.groupTree) == 0 {
			prevSelectedID = 0 // default to "All credentials" on first load
		}

		m.groupTree = buildGroupTree(m.groups, m.allItems)
		m.sidebar.SetNodes(m.groupTree)

		if !m.sidebar.SelectByID(prevSelectedID) {
			m.sidebar.SelectByID(0)
		}

		node := m.sidebar.Selected()
		m.selectedGroupID = node.id
		m.showAll = node.isAll

		m.refreshTable(true)

		switch {
		case m.pendingStatusMsg != "":
			pending := m.pendingStatusMsg
			m.pendingStatusMsg = ""

			return m, m.setStatus(pending)
		case len(m.allItems) == 0:
			m.statusMsg = "No credentials found."
		default:
			m.statusMsg = ""
		}

		return m, nil

	case credentialsLoadErrMsg:
		m.state = stateError
		m.err = msg.err

		return m, nil

	case groupCreatedMsg:
		m.pendingStatusMsg = fmt.Sprintf("Created group %q", msg.group.Name)
		m.state = stateLoading

		return m, tea.Batch(loadCredentialsCmd(m.client), m.spinner.Tick)

	case groupCreateErrMsg:
		m.state = stateCreateGroupForm

		return m, m.setStatus("Error creating group: " + msg.err.Error())

	case credentialMovedMsg:
		m.plaintext = ""

		groupName := "the new group"
		if msg.summary.Group != nil {
			groupName = msg.summary.Group.Name
		}

		m.pendingStatusMsg = fmt.Sprintf("Moved %s to %s", msg.summary.Site, groupName)
		m.state = stateLoading

		return m, tea.Batch(loadCredentialsCmd(m.client), m.spinner.Tick)

	case credentialMoveErrMsg:
		m.plaintext = ""
		m.state = stateBrowse

		return m, m.setStatus("Error moving credential: " + msg.err.Error())

	case credentialCreatedMsg:
		m.pendingStatusMsg = fmt.Sprintf("Added %s / %s", msg.summary.Site, msg.summary.Username)
		m.state = stateLoading

		return m, tea.Batch(loadCredentialsCmd(m.client), m.spinner.Tick)

	case credentialCreateErrMsg:
		m.state = stateAddForm

		return m, m.setStatus("Error creating credential: " + msg.err.Error())

	case credentialFetchedMsg:
		m.credential = msg.cred

		if m.vault.ready() {
			return m, tea.Batch(m.setBusy("Decrypting..."), decryptCmd(m.cfg.Active(), m.vault.privKey, "", m.credential))
		}

		m.busy = false
		m.state = statePasswordPrompt
		m.statusMsg = ""
		m.pwInput.Reset()
		m.pwInput.Focus()

		return m, textinput.Blink

	case credentialFetchErrMsg:
		m.state = stateBrowse

		return m, m.setStatus("Error fetching credential: " + msg.err.Error())

	case decryptResultMsg:
		return m.handleDecryptResult(msg)

	case serverLoginResultMsg:
		return m.handleServerLoginResult(msg)

	case spinner.TickMsg:
		if !m.busy && m.state != stateLoading {
			return m, nil // stop ticking while idle; setBusy restarts it
		}

		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)

		return m, cmd

	case statusExpireMsg:
		if msg.gen == m.statusGeneration {
			m.statusMsg = ""
		}

		return m, nil

	case copyTickMsg:
		return m.handleCopyTick(msg)

	case lockTickMsg:
		return m.handleLockTick()

	case tea.KeyMsg:
		m.lastActivity = time.Now()

		return m.handleKey(msg)
	}

	return m, nil
}

// handleCopyTick advances the post-copy countdown and, when it reaches zero,
// clears the clipboard unless the user has since copied something else.
func (m Model) handleCopyTick(msg copyTickMsg) (tea.Model, tea.Cmd) {
	if msg.gen != m.copyGeneration || m.copyCountdown == 0 {
		return m, nil
	}

	m.copyCountdown--

	if m.copyCountdown > 0 {
		m.statusMsg = copyCountdownStatus(m.copiedSite, m.copyCountdown)

		return m, copyTickCmd(msg.gen)
	}

	status := "Clipboard cleared."

	if content, ok := clipboard.ReadBack(); ok && content != m.copiedPassword {
		status = "" // clipboard holds something else now; leave it alone
	} else if err := clipboard.Clear(); err != nil {
		status = "Clipboard clear failed: " + err.Error()
	}

	m.cancelCopyCountdown()

	if status == "" {
		m.statusMsg = ""

		return m, nil
	}

	return m, m.setStatus(status)
}

// handleLockTick wipes the in-memory vault key (and any revealed plaintext)
// after lockTimeout of keyboard inactivity, then re-arms the check.
func (m Model) handleLockTick() (tea.Model, tea.Cmd) {
	cmds := []tea.Cmd{lockTickCmd()}

	timeout := m.lockTimeout()
	if timeout > 0 && m.vault.ready() && time.Since(m.lastActivity) >= timeout {
		m.vault.wipe()
		m.plaintext = ""
		m.revealed = false
		m.revealedCredID = 0
		m.credential = nil

		cmds = append(cmds, m.setStatus("Vault locked after inactivity."))
	}

	return m, tea.Batch(cmds...)
}

func (m Model) handleDecryptResult(msg decryptResultMsg) (tea.Model, tea.Cmd) {
	if msg.privKey != nil {
		m.vault.vaultKey = msg.vaultKey
		m.vault.privKey = msg.privKey
	}

	if msg.err != nil {
		if !m.vault.ready() {
			m.busy = false
			m.state = statePasswordPrompt
			m.statusMsg = "Incorrect master password, try again."
			m.pwInput.Reset()
			m.pwInput.Focus()

			return m, textinput.Blink
		}

		m.state = stateBrowse

		return m, m.setStatus("Error decrypting credential: " + msg.err.Error())
	}

	if m.pendingAction == actionCopy {
		m.state = stateBrowse

		if err := clipboard.Copy(msg.plaintext); err != nil {
			return m, m.setStatus("Clipboard copy failed: " + err.Error())
		}

		return m, m.startCopyCountdown(msg.plaintext, m.selected.site)
	}

	if m.pendingAction == actionMove {
		m.plaintext = msg.plaintext
		m.groupPickerMode = pickerMove
		m.busy = false

		writable := writableGroups(m.groups)

		otherCount := 0
		for _, g := range writable {
			if g.ID != m.selected.groupID {
				otherCount++
			}
		}

		if otherCount == 0 {
			m.plaintext = ""
			m.state = stateBrowse

			return m, m.setStatus("No other groups available to move to.")
		}

		m.setGroupPickerTree(m.groups, m.selected.groupID, "Move credential to group")
		m.state = stateGroupPicker
		m.statusMsg = ""

		return m, nil
	}

	m.plaintext = msg.plaintext
	m.revealed = true
	m.revealedCredID = m.selected.credID
	m.busy = false
	m.statusMsg = ""
	m.state = stateBrowse

	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyCtrlC {
		return m, tea.Quit
	}

	switch m.state {
	case stateBrowse:
		return m.handleBrowseKey(msg)
	case statePasswordPrompt:
		return m.handlePasswordPromptKey(msg)
	case stateError:
		return m.handleErrorKey(msg)
	case stateGroupPicker:
		return m.handleGroupPickerKey(msg)
	case stateAddForm:
		return m.handleAddFormKey(msg)
	case stateCreateGroupForm:
		return m.handleCreateGroupFormKey(msg)
	case stateSettings:
		return m.handleSettingsKey(msg)
	case stateServerPicker:
		return m.handleServerPickerKey(msg)
	case stateAddServerForm:
		return m.handleAddServerFormKey(msg)
	case stateAddServer2FA:
		return m.handleAddServer2FAKey(msg)
	}

	return m, nil
}

// handleBrowseKey handles keys in the main 3-pane browse view. App-level
// keys (tab, /, v, c, u, a, g, m, ?, q) are reserved and never forwarded to
// the table or sidebar; only navigation keys are routed to the focused pane.
func (m Model) handleBrowseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.showHelp {
		m.showHelp = false

		return m, nil
	}

	if m.filterEditing {
		return m.handleFilterKey(msg)
	}

	switch msg.String() {
	case "q":
		return m, tea.Quit

	case "?":
		m.showHelp = true

		return m, nil

	case "esc":
		if m.filterQuery != "" {
			m.filterQuery = ""
			m.filterInput.Reset()
			m.refreshTable(true)
		}

		return m, nil

	case "tab":
		if m.focus == focusSidebar {
			m.focus = focusTable
		} else {
			m.focus = focusSidebar
		}

		return m, nil

	case "left", "h":
		if m.width >= verySmallThreshold {
			m.focus = focusSidebar
		}

		return m, nil

	case "right", "l":
		m.focus = focusTable

		return m, nil

	case "enter":
		if m.focus == focusSidebar {
			m.focus = focusTable

			return m, nil
		}

		return m.startReveal()

	case "/":
		m.filterEditing = true
		m.filterInput.Focus()

		return m, textinput.Blink

	case "v":
		return m.startReveal()

	case "c":
		return m.startCopy()

	case "u":
		return m.copyUsername()

	case "a":
		if !m.showAll {
			for _, g := range m.groups {
				if g.ID == m.selectedGroupID {
					m.selectedGroup = g

					break
				}
			}

			m.resetAddForm()
			m.state = stateAddForm
			m.statusMsg = ""

			return m, textinput.Blink
		}

		writable := writableGroups(m.groups)

		switch len(writable) {
		case 0:
			return m, m.setStatus("No groups available to add a credential to.")
		case 1:
			m.selectedGroup = writable[0]
			m.resetAddForm()
			m.state = stateAddForm
			m.statusMsg = ""

			return m, textinput.Blink
		default:
			m.setGroupPickerTree(m.groups, 0, "Add credential to group")
			m.groupPickerMode = pickerAdd
			m.state = stateGroupPicker
			m.statusMsg = ""

			return m, nil
		}

	case "g":
		if m.showAll {
			m.newGroupParentID = nil
			m.newGroupParent = "(top-level)"
		} else {
			id := m.selectedGroupID
			m.newGroupParentID = &id
			m.newGroupParent = "(top-level)"

			for _, g := range m.groups {
				if g.ID == id {
					m.newGroupParent = g.Name

					break
				}
			}
		}

		m.groupNameInput.Reset()
		m.groupNameInput.Focus()
		m.state = stateCreateGroupForm
		m.statusMsg = ""

		return m, textinput.Blink

	case "m":
		return m.startMove()

	case "s":
		return m.openSettings()

	case "S":
		return m.openServerPicker()

	case "up", "k", "down", "j", "pgup", "pgdown":
		if m.focus == focusSidebar {
			return m.handleSidebarNav(msg)
		}

		return m.handleTableNav(msg)
	}

	return m, nil
}

// handleSidebarNav moves the sidebar cursor and, on a group change, resets
// the table to row 0 and resets reveal state.
func (m Model) handleSidebarNav(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	prev := m.sidebar.Selected()

	switch msg.String() {
	case "up", "k":
		m.sidebar.MoveUp()
	case "down", "j":
		m.sidebar.MoveDown()
	case "pgup":
		for i := 0; i < m.sidebar.height; i++ {
			m.sidebar.MoveUp()
		}
	case "pgdown":
		for i := 0; i < m.sidebar.height; i++ {
			m.sidebar.MoveDown()
		}
	}

	node := m.sidebar.Selected()
	if node.id != prev.id {
		m.selectedGroupID = node.id
		m.showAll = node.isAll
		m.refreshTable(true)
	}

	return m, nil
}

// handleTableNav forwards navigation keys to the table and resyncs
// m.selected, resetting reveal state when the highlighted row changes.
func (m Model) handleTableNav(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	prevID := m.selected.credID

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)

	m.updateSelectedFromCursor()

	if m.selected.credID != prevID {
		m.revealed = false
		m.revealedCredID = 0
		m.plaintext = ""
	}

	return m, cmd
}

// handleFilterKey handles input while the "/" filter box has focus. esc
// clears the filter and restores group-based filtering; enter keeps the
// filter active and moves focus to the table.
func (m Model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filterEditing = false
		m.filterQuery = ""
		m.filterInput.Reset()
		m.filterInput.Blur()
		m.refreshTable(true)

		return m, nil

	case "enter":
		m.filterEditing = false
		m.filterInput.Blur()
		m.focus = focusTable

		return m, nil
	}

	var cmd tea.Cmd
	m.filterInput, cmd = m.filterInput.Update(msg)
	m.filterQuery = m.filterInput.Value()
	m.refreshTable(true)

	return m, cmd
}

func (m Model) handlePasswordPromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.pwInput.Reset()
		m.state = stateBrowse
		m.statusMsg = ""

		return m, nil

	case "enter":
		password := m.pwInput.Value()
		m.pwInput.Reset()

		return m, tea.Batch(m.setBusy("Decrypting..."), decryptCmd(m.cfg.Active(), nil, password, m.credential))
	}

	var cmd tea.Cmd
	m.pwInput, cmd = m.pwInput.Update(msg)

	return m, cmd
}

func (m Model) handleGroupPickerKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		if m.groupPickerMode == pickerMove {
			m.plaintext = ""
			m.groupPickerMode = pickerAdd
		}

		m.state = stateBrowse
		m.statusMsg = ""

		return m, nil

	case "up", "k":
		m.groupPicker.MoveUp()

		return m, nil

	case "down", "j":
		m.groupPicker.MoveDown()

		return m, nil

	case "enter":
		selected := m.groupPicker.Selected()
		if selected.disabled || selected.isSeparator {
			return m, nil
		}

		if m.groupPickerMode == pickerMove {
			m.groupPickerMode = pickerAdd

			return m, tea.Batch(
				m.setBusy("Moving credential..."),
				moveCredentialCmd(m.client, m.selected.credID, selected.id, m.plaintext),
			)
		}

		for _, g := range m.groups {
			if g.ID == selected.id {
				m.selectedGroup = g

				break
			}
		}

		m.resetAddForm()
		m.state = stateAddForm
		m.statusMsg = ""

		return m, textinput.Blink
	}

	return m, nil
}

func (m Model) handleAddFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		for i := range m.addForm {
			m.addForm[i].Reset()
		}

		m.state = stateBrowse
		m.statusMsg = ""

		return m, nil

	case "tab", "down":
		m.addForm[m.addFocus].Blur()
		m.addFocus = (m.addFocus + 1) % numAddFields
		m.addForm[m.addFocus].Focus()

		return m, textinput.Blink

	case "shift+tab", "up":
		m.addForm[m.addFocus].Blur()
		m.addFocus = (m.addFocus - 1 + numAddFields) % numAddFields
		m.addForm[m.addFocus].Focus()

		return m, textinput.Blink

	case "enter":
		site := strings.TrimSpace(m.addForm[addFieldSite].Value())
		username := strings.TrimSpace(m.addForm[addFieldUsername].Value())
		password := m.addForm[addFieldPassword].Value()
		notes := strings.TrimSpace(m.addForm[addFieldNotes].Value())

		if site == "" || username == "" || password == "" {
			return m, m.setStatus("Site, username, and password are required.")
		}

		return m, tea.Batch(
			m.setBusy("Creating credential..."),
			createCredentialCmd(m.client, m.selectedGroup.ID, site, username, password, notes),
		)
	}

	var cmd tea.Cmd
	m.addForm[m.addFocus], cmd = m.addForm[m.addFocus].Update(msg)

	return m, cmd
}

func (m Model) handleCreateGroupFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.groupNameInput.Reset()
		m.state = stateBrowse
		m.statusMsg = ""

		return m, nil

	case "enter":
		name := strings.TrimSpace(m.groupNameInput.Value())
		if name == "" {
			return m, m.setStatus("Group name is required.")
		}

		return m, tea.Batch(m.setBusy("Creating group..."), createGroupCmd(m.client, name, m.newGroupParentID))
	}

	var cmd tea.Cmd
	m.groupNameInput, cmd = m.groupNameInput.Update(msg)

	return m, cmd
}

func (m Model) handleErrorKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "r":
		m.state = stateLoading
		m.err = nil

		return m, loadCredentialsCmd(m.client)
	case "q", "esc":
		return m, tea.Quit
	}

	return m, nil
}

func (m Model) View() string {
	switch m.state {
	case stateLoading:
		return m.spinner.View() + " " + styleHelp.Render("Loading credentials...")
	case stateBrowse:
		if m.showHelp {
			return overlayCenter(renderBrowse(m), renderHelp(), m.width, m.height)
		}

		return renderBrowse(m)
	case statePasswordPrompt:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderPasswordPrompt(m.pwInput.View(), m.statusMsg)), m.width, m.height)
	case stateError:
		return renderError(m.err, m.statusMsg)
	case stateGroupPicker:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderGroupPicker(m)), m.width, m.height)
	case stateAddForm:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderAddForm(m.selectedGroup, m.addForm[:], m.statusMsg)), m.width, m.height)
	case stateCreateGroupForm:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderCreateGroupForm(m.newGroupParent, m.groupNameInput, m.statusMsg)), m.width, m.height)
	case stateSettings:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderSettings(m)), m.width, m.height)
	case stateServerPicker:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderServerPicker(m)), m.width, m.height)
	case stateAddServerForm:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderAddServerForm(m.addServerForm[:], m.statusMsg)), m.width, m.height)
	case stateAddServer2FA:
		return overlayCenter(renderBrowse(m), styleModalBox.Render(renderAddServer2FA(m.addServer2FAInput, m.statusMsg)), m.width, m.height)
	}

	return ""
}
