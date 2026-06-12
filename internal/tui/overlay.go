package tui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// overlayCenter composites fg on top of bg, centered within a canvas of
// width x height cells. Lines (and columns within those lines) covered by fg
// have their bg content replaced; the rest of bg passes through unchanged.
func overlayCenter(bg, fg string, width, height int) string {
	bgLines := strings.Split(bg, "\n")
	fgLines := strings.Split(fg, "\n")

	fgW := 0
	for _, l := range fgLines {
		fgW = max(fgW, ansi.StringWidth(l))
	}

	fgH := len(fgLines)

	x := max((width-fgW)/2, 0)
	y := max((height-fgH)/2, 0)

	for len(bgLines) < y+fgH {
		bgLines = append(bgLines, "")
	}

	for i, fgLine := range fgLines {
		bgLines[y+i] = overlayLine(bgLines[y+i], fgLine, x)
	}

	return strings.Join(bgLines, "\n")
}

// overlayLine splices fgLine onto bgLine starting at column x, replacing
// whatever bg content occupied those columns.
func overlayLine(bgLine, fgLine string, x int) string {
	fgW := ansi.StringWidth(fgLine)

	left := ansi.Truncate(bgLine, x, "")
	if w := ansi.StringWidth(left); w < x {
		left += strings.Repeat(" ", x-w)
	}

	bgW := ansi.StringWidth(bgLine)
	right := ansi.Cut(bgLine, x+fgW, max(bgW, x+fgW))

	return left + fgLine + right
}
