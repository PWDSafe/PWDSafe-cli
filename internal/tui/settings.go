package tui

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"pwdsafe-cli/internal/config"
)

var hexColorPattern = regexp.MustCompile(`^#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})$`)

// settingsCustomIndex is the cursor position of the "custom hex" row, just
// past the preset swatches.
func settingsCustomIndex() int {
	return len(PresetAccentColors)
}

// currentAccentColor returns the configured accent color, or the default if
// unset.
func (m Model) currentAccentColor() string {
	if m.cfg.AccentColor != nil {
		return *m.cfg.AccentColor
	}

	return DefaultAccentColor
}

// openSettings switches to the settings view, placing the cursor on the
// preset matching the current accent color (or the custom row otherwise).
func (m Model) openSettings() (tea.Model, tea.Cmd) {
	current := m.currentAccentColor()

	m.settingsCursor = settingsCustomIndex()

	for i, p := range PresetAccentColors {
		if strings.EqualFold(p.Color, current) {
			m.settingsCursor = i

			break
		}
	}

	m.settingsEditingHex = false
	m.settingsCustomInput.SetValue(current)
	m.settingsCustomInput.Blur()
	m.state = stateSettings
	m.statusMsg = ""

	return m, nil
}

// applyAccentColor switches the live theme to color and persists it to the
// config file.
func (m *Model) applyAccentColor(color string) tea.Cmd {
	SetAccentColor(color)
	m.table.SetStyles(tableStyles())
	m.cfg.AccentColor = &color
	m.settingsCustomInput.SetValue(color)

	if err := config.Save(m.cfg); err != nil {
		return m.setStatus("Saved color but failed to write config: " + err.Error())
	}

	return m.setStatus("Accent color updated.")
}

func (m Model) handleSettingsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.settingsEditingHex {
		switch msg.String() {
		case "esc":
			m.settingsEditingHex = false
			m.settingsCustomInput.Blur()
			m.statusMsg = ""

			return m, nil

		case "enter":
			hex := strings.TrimSpace(m.settingsCustomInput.Value())
			if !hexColorPattern.MatchString(hex) {
				return m, m.setStatus("Invalid hex color, expected e.g. #FF5FAF.")
			}

			m.settingsEditingHex = false
			m.settingsCustomInput.Blur()

			return m, m.applyAccentColor(hex)
		}

		var cmd tea.Cmd
		m.settingsCustomInput, cmd = m.settingsCustomInput.Update(msg)

		return m, cmd
	}

	switch msg.String() {
	case "esc", "q":
		m.state = stateBrowse
		m.statusMsg = ""

		return m, nil

	case "up", "k":
		if m.settingsCursor > 0 {
			m.settingsCursor--
		}

		return m, nil

	case "down", "j":
		if m.settingsCursor < settingsCustomIndex() {
			m.settingsCursor++
		}

		return m, nil

	case "enter":
		if m.settingsCursor == settingsCustomIndex() {
			m.settingsEditingHex = true
			m.settingsCustomInput.Focus()

			return m, textinput.Blink
		}

		return m, m.applyAccentColor(PresetAccentColors[m.settingsCursor].Color)
	}

	return m, nil
}

// renderSettings renders the accent-color picker: 8 preset swatches plus a
// custom hex code entry.
func renderSettings(m Model) string {
	var b strings.Builder

	b.WriteString(styleTitle.Render("Settings") + "\n\n")
	b.WriteString(styleLabel.Render("Accent color") + "\n\n")

	current := m.currentAccentColor()

	for i, p := range PresetAccentColors {
		cursor := "  "
		if i == m.settingsCursor {
			cursor = "> "
		}

		swatch := lipgloss.NewStyle().Background(lipgloss.Color(p.Color)).Render("    ")

		label := fmt.Sprintf("%-7s %s", p.Name, p.Color)
		if strings.EqualFold(p.Color, current) {
			label = styleSwatchSelected.Render(label + " (current)")
		}

		fmt.Fprintf(&b, "%s%s  %s\n", cursor, swatch, label)
	}

	b.WriteString("\n")

	cursor := "  "
	if m.settingsCursor == settingsCustomIndex() {
		cursor = "> "
	}

	switch {
	case m.settingsEditingHex:
		fmt.Fprintf(&b, "%sCustom hex: %s\n", cursor, m.settingsCustomInput.View())
	default:
		label := fmt.Sprintf("Custom hex: %s", current)
		if !presetMatches(current) {
			label = styleSwatchSelected.Render(label + " (current)")
		}

		fmt.Fprintf(&b, "%s%s\n", cursor, label)
	}

	if m.statusMsg != "" {
		b.WriteString("\n" + styleStatus.Render(m.statusMsg) + "\n")
	}

	if m.settingsEditingHex {
		b.WriteString("\n" + styleHelp.Render("enter apply · esc cancel"))
	} else {
		b.WriteString("\n" + styleHelp.Render("↑/↓ select · enter apply/edit · esc back"))
	}

	return b.String()
}

func presetMatches(color string) bool {
	for _, p := range PresetAccentColors {
		if strings.EqualFold(p.Color, color) {
			return true
		}
	}

	return false
}
