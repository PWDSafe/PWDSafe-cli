package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// sidebarModel renders the group tree as a static, always-visible list with
// a single selectable cursor row. It is intentionally simpler than
// bubbles/list, which is built around filtering/pagination/help that this
// tree doesn't need.
type sidebarModel struct {
	nodes  []groupNode
	cursor int
	offset int
	width  int
	height int
}

// SetNodes replaces the displayed tree, clamping the cursor/offset to the
// new bounds.
func (s *sidebarModel) SetNodes(nodes []groupNode) {
	s.nodes = nodes

	if s.cursor >= len(nodes) {
		s.cursor = len(nodes) - 1
	}

	if s.cursor < 0 {
		s.cursor = 0
	}

	for s.cursor < len(s.nodes)-1 && (s.nodes[s.cursor].isSeparator || s.nodes[s.cursor].disabled) {
		s.cursor++
	}

	for s.cursor > 0 && (s.nodes[s.cursor].isSeparator || s.nodes[s.cursor].disabled) {
		s.cursor--
	}

	s.clampOffset()
}

// SelectByID moves the cursor to the node with the given id, if present,
// returning whether it was found.
func (s *sidebarModel) SelectByID(id int) bool {
	for i, n := range s.nodes {
		if n.id == id {
			s.cursor = i
			s.clampOffset()

			return true
		}
	}

	return false
}

func (s *sidebarModel) MoveUp() {
	for i := s.cursor - 1; i >= 0; i-- {
		if !s.nodes[i].isSeparator && !s.nodes[i].disabled {
			s.cursor = i

			break
		}
	}

	s.clampOffset()
}

func (s *sidebarModel) MoveDown() {
	for i := s.cursor + 1; i < len(s.nodes); i++ {
		if !s.nodes[i].isSeparator && !s.nodes[i].disabled {
			s.cursor = i

			break
		}
	}

	s.clampOffset()
}

func (s *sidebarModel) clampOffset() {
	if s.height <= 0 {
		return
	}

	if s.cursor < s.offset {
		s.offset = s.cursor
	}

	if s.cursor >= s.offset+s.height {
		s.offset = s.cursor - s.height + 1
	}
}

// Selected returns the currently highlighted node. Safe to call on an empty
// tree (returns the zero value).
func (s sidebarModel) Selected() groupNode {
	if s.cursor < 0 || s.cursor >= len(s.nodes) {
		return groupNode{}
	}

	return s.nodes[s.cursor]
}

func (s sidebarModel) View(focused bool) string {
	end := len(s.nodes)
	if s.height > 0 && s.offset+s.height < end {
		end = s.offset + s.height
	}

	start := s.offset
	if start > end {
		start = end
	}

	var b strings.Builder

	for i := start; i < end; i++ {
		n := s.nodes[i]

		var line string
		if n.isSeparator {
			line = strings.Repeat("─", s.width)
		} else {
			line = renderSidebarLine(n, s.width)
		}

		switch {
		case n.isSeparator:
			line = styleSidebarSeparator.Render(line)
		case n.disabled:
			line = styleHelp.Render(line)
		case i == s.cursor && focused:
			line = styleSidebarSelected.Render(line)
		case i == s.cursor:
			line = styleSidebarSelectedUnfocused.Render(line)
		case n.isAll:
			line = styleAllEntry.Render(line)
		}

		b.WriteString(line)

		if i < end-1 {
			b.WriteString("\n")
		}
	}

	return b.String()
}

// renderSidebarLine formats a single row as "<indent><name> [<count>]",
// padded or truncated (with an ellipsis on the name) to fit exactly within
// width columns, with the count right-aligned at the edge of the pane.
func renderSidebarLine(n groupNode, width int) string {
	indent := strings.Repeat("  ", n.depth)

	count := ""
	if n.count > 0 {
		count = fmt.Sprintf("[%d]", n.count)
	}

	if width <= 0 {
		if count == "" {
			return indent + n.name
		}

		return indent + n.name + " " + count
	}

	gap := 0
	if count != "" {
		gap = 1
	}

	nameBudget := width - lipgloss.Width(indent) - lipgloss.Width(count) - gap
	if nameBudget < 0 {
		nameBudget = 0
	}

	name := n.name
	if lipgloss.Width(name) > nameBudget {
		name = truncateWithEllipsis(name, nameBudget)
	}

	left := indent + name

	if count == "" {
		return left
	}

	pad := width - lipgloss.Width(left) - lipgloss.Width(count)
	if pad < 1 {
		pad = 1
	}

	return left + strings.Repeat(" ", pad) + count
}

// truncateWithEllipsis shortens s to fit within width columns, appending an
// ellipsis if it had to cut content.
func truncateWithEllipsis(s string, width int) string {
	if width <= 1 {
		return s[:0]
	}

	if lipgloss.Width(s) <= width {
		return s
	}

	runes := []rune(s)
	for lipgloss.Width(string(runes))+1 > width && len(runes) > 0 {
		runes = runes[:len(runes)-1]
	}

	return string(runes) + "…"
}
