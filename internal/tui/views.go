package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"

	"pwdsafe-cli/internal/api"
)

// helpSections is the keybinding reference shown by the "?" overlay.
var helpSections = []struct {
	title    string
	bindings [][2]string
}{
	{"Navigation", [][2]string{
		{"tab", "switch pane"},
		{"←/h · →/l", "focus sidebar / table"},
		{"↑/k · ↓/j", "move up / down"},
		{"pgup/pgdn", "page up / down"},
		{"enter", "reveal password (or focus table)"},
	}},
	{"Credentials", [][2]string{
		{"v", "reveal/hide password"},
		{"c", "copy password (clipboard auto-clears after 30s)"},
		{"u", "copy username"},
		{"t", "copy TOTP code (auto-clears after 30s)"},
		{"/", "filter credentials"},
	}},
	{"Organize", [][2]string{
		{"a", "add credential"},
		{"g", "create group"},
		{"m", "move credential to another group"},
	}},
	{"General", [][2]string{
		{"s", "settings (accent color)"},
		{"S", "switch server"},
		{"?", "toggle this help"},
		{"esc", "clear filter / cancel"},
		{"q", "quit"},
	}},
}

// renderHelp renders the keybinding reference as a modal box.
func renderHelp() string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Keyboard shortcuts") + "\n")

	for _, section := range helpSections {
		b.WriteString("\n" + styleHelpSection.Render(section.title) + "\n")

		for _, kb := range section.bindings {
			fmt.Fprintf(&b, "  %s %s\n", styleHelpKey.Render(fmt.Sprintf("%-11s", kb[0])), kb[1])
		}
	}

	b.WriteString("\n" + styleHelp.Render("press any key to close"))

	return styleModalBox.Render(b.String())
}

// renderGroupPicker renders the group-selection table shown when adding a
// credential to one of several groups, or moving a credential to another
// group.
func renderGroupPicker(m Model) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render(m.groupPickerTitle) + "\n\n")
	b.WriteString(m.groupPicker.View(true))
	b.WriteString("\n\n" + styleHelp.Render("↑/↓ select · enter choose · esc cancel"))

	return b.String()
}

func renderPasswordPrompt(input string, statusMsg string) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Master password") + "\n\n")
	b.WriteString("Enter your master password to unlock the vault for this session.\n\n")
	b.WriteString(input + "\n")

	if statusMsg != "" {
		b.WriteString("\n" + styleError.Render(statusMsg) + "\n")
	}

	b.WriteString("\n" + styleHelp.Render("enter confirm · esc back"))

	return b.String()
}

func renderAddForm(group api.Group, fields []textinput.Model, statusMsg string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s %s\n\n", styleTitle.Render("New credential in"), group.Name)

	labels := []string{"Name:    ", "URL:     ", "Username:", "Password:", "Notes:   "}

	for i, f := range fields {
		fmt.Fprintf(&b, "%s %s\n", styleLabel.Render(labels[i]), f.View())
	}

	if statusMsg != "" {
		b.WriteString("\n" + styleStatus.Render(statusMsg) + "\n")
	}

	b.WriteString("\n" + styleHelp.Render("tab/shift+tab next/prev field · enter save · esc cancel"))

	return b.String()
}

func renderCreateGroupForm(parentLabel string, input textinput.Model, statusMsg string) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("New group") + "\n\n")

	fmt.Fprintf(&b, "%s %s\n", styleLabel.Render("Parent:"), parentLabel)
	fmt.Fprintf(&b, "%s %s\n", styleLabel.Render("Name:  "), input.View())

	if statusMsg != "" {
		b.WriteString("\n" + styleStatus.Render(statusMsg) + "\n")
	}

	b.WriteString("\n" + styleHelp.Render("enter create · esc cancel"))

	return b.String()
}

func renderError(m Model) string {
	var b strings.Builder

	b.WriteString(styleError.Render("Error: "+m.err.Error()) + "\n")

	if m.statusMsg != "" {
		b.WriteString("\n" + styleStatus.Render(m.statusMsg) + "\n")
	}

	help := "r retry · q quit"
	if len(m.cfg.Servers) > 1 {
		help = "r retry · s switch server · q quit"
	}

	b.WriteString("\n" + styleHelp.Render(help))

	return b.String()
}
