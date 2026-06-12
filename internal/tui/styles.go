package tui

import (
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
)

// DefaultAccentColor is used when the user hasn't configured a custom accent
// color.
const DefaultAccentColor = "205"

// PresetAccentColors are the choices offered in the settings view, in
// addition to a custom hex code.
var PresetAccentColors = []struct {
	Name  string
	Color string
}{
	{"Pink", "#FF5FAF"},
	{"Red", "#FF5F5F"},
	{"Orange", "#FFAF5F"},
	{"Yellow", "#FFFF5F"},
	{"Green", "#5FFF87"},
	{"Cyan", "#5FFFFF"},
	{"Blue", "#5FAFFF"},
	{"Purple", "#AF87FF"},
}

var (
	styleStatus = lipgloss.NewStyle().
			Foreground(lipgloss.Color("242")).
			Italic(true)

	styleError = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("9"))

	styleHelp = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	styleLabel = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("245"))

	stylePassword = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("42"))

	stylePasswordMasked = lipgloss.NewStyle().
				Foreground(lipgloss.Color("242"))

	styleSidebarPane = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240")).
				Padding(0, 1)

	styleTablePane = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240"))

	styleDetailPane = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)

	styleSidebarSelectedUnfocused = lipgloss.NewStyle().
					Bold(true).
					Foreground(lipgloss.Color("255")).
					Background(lipgloss.Color("238"))

	styleAllEntry = lipgloss.NewStyle().Bold(true)

	styleSidebarSeparator = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	styleHelpSection = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("245"))
)

// Accent-dependent styles. These are (re)built by SetAccentColor, which is
// called once at startup with the configured color and again whenever the
// user changes it from the settings view.
var (
	styleTitle              lipgloss.Style
	styleSidebarPaneFocused lipgloss.Style
	styleTablePaneFocused   lipgloss.Style
	styleSidebarSelected    lipgloss.Style
	styleModalBox           lipgloss.Style
	styleHelpKey            lipgloss.Style
	styleSpinner            lipgloss.Style
	styleSwatchSelected     lipgloss.Style
)

func init() {
	SetAccentColor(DefaultAccentColor)
}

// SetAccentColor rebuilds all accent-dependent styles using the given
// lipgloss color spec (a hex code such as "#FF5FAF" or an ANSI-256 code such
// as "205").
func SetAccentColor(color string) {
	c := lipgloss.Color(color)

	styleTitle = lipgloss.NewStyle().
		Bold(true).
		Foreground(c)

	styleSidebarPaneFocused = styleSidebarPane.
		BorderForeground(c)

	styleTablePaneFocused = styleTablePane.
		BorderForeground(c)

	styleSidebarSelected = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("0")).
		Background(c)

	styleModalBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(c).
		Padding(1, 3)

	styleHelpKey = lipgloss.NewStyle().
		Foreground(c)

	styleSpinner = lipgloss.NewStyle().
		Foreground(c)

	styleSwatchSelected = lipgloss.NewStyle().
		Bold(true).
		Foreground(c)
}

// tableStyles returns the bubbles/table styles to use for the credentials
// table, with the row-selection highlight following the accent color.
func tableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("0")).
		Background(styleSwatchSelected.GetForeground())

	return s
}
