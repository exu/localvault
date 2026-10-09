package unlocker

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// pinentryPrograms are tried in order; pinentry-curses is skipped because it needs a terminal.
var pinentryPrograms = []string{"pinentry-gnome3", "pinentry-qt", "pinentry-gtk", "pinentry-gtk-2"}

var (
	readDir = os.ReadDir
	setenv  = os.Setenv
	getuid  = os.Getuid
)

// runPinentry runs a pinentry program and returns the entered password; replaced in tests.
var runPinentry = func(prog, desc, prompt string) ([]byte, error) {
	c := exec.Command(prog)
	in, err := c.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := c.Start(); err != nil {
		return nil, err
	}
	pw, xerr := pinentryExchange(struct {
		io.Reader
		io.Writer
	}{out, in}, desc, prompt)
	in.Close()
	c.Wait()
	return pw, xerr
}

func assuanEscape(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func assuanUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// pinentryExchange speaks the Assuan pinentry protocol over rw and returns the entered password.
func pinentryExchange(rw io.ReadWriter, desc, prompt string) ([]byte, error) {
	r := bufio.NewReader(rw)
	readReply := func() (string, error) {
		var data string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("unlocker: pinentry closed unexpectedly: %w", err)
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "D "):
				data += assuanUnescape(line[2:])
			case line == "OK" || strings.HasPrefix(line, "OK "):
				return data, nil
			case strings.HasPrefix(line, "ERR "):
				low := strings.ToLower(line)
				if strings.Contains(low, "cancel") || strings.Contains(low, "timeout") {
					return "", ErrCancelled
				}
				return "", fmt.Errorf("unlocker: pinentry: %s", line)
			}
		}
	}
	if _, err := readReply(); err != nil {
		return nil, err
	}
	for _, cmd := range []string{
		"SETTITLE localvault",
		"SETDESC " + assuanEscape(desc),
		"SETPROMPT " + assuanEscape(prompt),
		fmt.Sprintf("SETTIMEOUT %d", dialogTimeout),
		"GETPIN",
	} {
		if _, err := fmt.Fprintln(rw, cmd); err != nil {
			return nil, err
		}
		if cmd == "GETPIN" {
			pw, err := readReply()
			if err != nil {
				return nil, err
			}
			fmt.Fprintln(rw, "BYE")
			return []byte(pw), nil
		}
		if _, err := readReply(); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("unlocker: pinentry: unreachable")
}

// findPinentry returns the first available GUI pinentry program.
func findPinentry() (string, bool) {
	for _, p := range pinentryPrograms {
		if _, err := lookPath(p); err == nil {
			return p, true
		}
	}
	return "", false
}

// ensureDisplayEnv finds a graphical session when the env lacks one (ssh, agents) and reports whether one exists.
func ensureDisplayEnv() bool {
	if getenv("WAYLAND_DISPLAY") != "" || getenv("DISPLAY") != "" {
		return true
	}
	dir := getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = fmt.Sprintf("/run/user/%d", getuid())
	}
	entries, err := readDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "wayland-") && !strings.HasSuffix(name, ".lock") {
			setenv("XDG_RUNTIME_DIR", dir)
			setenv("WAYLAND_DISPLAY", name)
			return true
		}
	}
	if m, _ := filepath.Glob("/tmp/.X11-unix/X0"); len(m) > 0 {
		setenv("DISPLAY", ":0")
		return true
	}
	return false
}
