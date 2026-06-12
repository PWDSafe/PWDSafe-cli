// Package clipboard copies text to the system clipboard. It prefers the
// platform's native clipboard tool (wl-copy, xclip, xsel, pbcopy) when one is
// available, because terminal support for the OSC 52 escape sequence is
// spotty (VTE-based terminals such as GNOME Terminal ignore it). OSC 52 is
// kept as a fallback since it is the only mechanism that works over SSH and
// inside tmux without any tools on the local machine.
package clipboard

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// tool describes an external clipboard utility: how to write to the
// clipboard, how to read it back, and how to clear it.
type tool struct {
	copyArgs  []string
	pasteArgs []string
	clearArgs []string
}

var candidates = []struct {
	env string // required environment variable, empty means none
	bin string
	tool
}{
	{
		env: "WAYLAND_DISPLAY",
		bin: "wl-copy",
		tool: tool{
			copyArgs:  []string{"wl-copy"},
			pasteArgs: []string{"wl-paste", "--no-newline"},
			clearArgs: []string{"wl-copy", "--clear"},
		},
	},
	{
		env: "DISPLAY",
		bin: "xclip",
		tool: tool{
			copyArgs:  []string{"xclip", "-selection", "clipboard"},
			pasteArgs: []string{"xclip", "-o", "-selection", "clipboard"},
		},
	},
	{
		env: "DISPLAY",
		bin: "xsel",
		tool: tool{
			copyArgs:  []string{"xsel", "--clipboard", "--input"},
			pasteArgs: []string{"xsel", "--clipboard", "--output"},
			clearArgs: []string{"xsel", "--clipboard", "--clear"},
		},
	},
}

// findTool picks the clipboard utility to use, or nil to fall back to
// OSC 52. Resolved once per process.
var findTool = sync.OnceValue(func() *tool {
	for i := range candidates {
		c := &candidates[i]
		if c.env != "" && os.Getenv(c.env) == "" {
			continue
		}

		if _, err := exec.LookPath(c.bin); err != nil {
			continue
		}

		return &c.tool
	}

	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("pbcopy"); err == nil {
			return &tool{
				copyArgs:  []string{"pbcopy"},
				pasteArgs: []string{"pbpaste"},
			}
		}
	}

	return nil
})

// Copy writes s to the system clipboard, falling back to OSC 52 if no
// clipboard tool is available or the tool fails.
func Copy(s string) error {
	if t := findTool(); t != nil {
		cmd := exec.Command(t.copyArgs[0], t.copyArgs[1:]...)
		cmd.Stdin = strings.NewReader(s)

		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	return copyOSC52(s)
}

// Clear empties the system clipboard.
func Clear() error {
	t := findTool()
	if t == nil {
		return copyOSC52("")
	}

	if t.clearArgs != nil {
		if err := exec.Command(t.clearArgs[0], t.clearArgs[1:]...).Run(); err == nil {
			return nil
		}
	}

	return Copy("")
}

// ReadBack returns the clipboard's current contents, with ok=false when the
// clipboard cannot be read (OSC 52 fallback mode, or the paste tool failed).
func ReadBack() (content string, ok bool) {
	t := findTool()
	if t == nil || t.pasteArgs == nil {
		return "", false
	}

	out, err := exec.Command(t.pasteArgs[0], t.pasteArgs[1:]...).Output()
	if err != nil {
		return "", false
	}

	return string(out), true
}

// copyOSC52 writes an OSC 52 escape sequence setting the clipboard to s. It
// writes to /dev/tty so the sequence reaches the terminal even if the
// command's stdout/stderr are redirected, falling back to stderr if /dev/tty
// is unavailable. tmux (since 2.6, with its default `set-clipboard`) passes
// OSC 52 through to the outer terminal on its own, so the sequence is sent
// unwrapped; wrapping it in tmux's DCS passthrough would instead require
// `allow-passthrough on`, which is off by default.
func copyOSC52(s string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	seq := fmt.Sprintf("\x1b]52;c;%s\x07", encoded)

	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		_, err := fmt.Fprint(os.Stderr, seq)
		return err
	}
	defer tty.Close()

	_, err = fmt.Fprint(tty, seq)

	return err
}
