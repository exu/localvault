package unlocker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// ErrCancelled is returned when the user dismisses or times out the password dialog.
var ErrCancelled = errors.New("unlock cancelled")

// PromptMessage is shown above the password field in the GUI dialog.
var PromptMessage string

const dialogScript = `on run argv
	tell current application to activate
	set r to display dialog (item 1 of argv) default answer "" with hidden answer with title "localvault" buttons {"Cancel", "Unlock"} default button "Unlock" cancel button "Cancel" giving up after 60
	if gave up of r then error "timeout" number -128
	return text returned of r
end run`

const dialogTimeout = 60

var (
	goos     = runtime.GOOS
	lookPath = exec.LookPath
	getenv   = os.Getenv
)

// runDialog runs a dialog program and returns its stdout; exit 1 or a timeout code means the user cancelled. Replaced in tests.
var runDialog = func(name string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && (ee.ExitCode() == 1 || ee.ExitCode() == 5) && !strings.Contains(errb.String(), "rror:") {
			return nil, ErrCancelled
		}
		if strings.Contains(errb.String(), "-128") || strings.Contains(errb.String(), "canceled") {
			return nil, ErrCancelled
		}
		return nil, fmt.Errorf("unlocker: dialog failed: %s", strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// linuxDialog picks the first available GUI password dialog program.
func linuxDialog(msg string) (string, []string, error) {
	if getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
		return "", nil, errors.New("unlocker: no terminal and no display for a password dialog")
	}
	timeout := fmt.Sprint(dialogTimeout)
	if _, err := lookPath("zenity"); err == nil {
		return "zenity", []string{"--password", "--title=localvault", "--text=" + msg, "--timeout=" + timeout}, nil
	}
	if _, err := lookPath("kdialog"); err == nil {
		return "kdialog", []string{"--title", "localvault", "--password", msg}, nil
	}
	if _, err := lookPath("yad"); err == nil {
		return "yad", []string{"--entry", "--hide-text", "--title=localvault", "--text=" + msg, "--timeout=" + timeout, "--button=Cancel:1", "--button=Unlock:0"}, nil
	}
	return "", nil, errors.New("unlocker: no terminal and no dialog program found, install zenity or kdialog")
}

func promptGUI(label string) ([]byte, error) {
	msg := strings.TrimSpace(PromptMessage + "\n\n" + label)
	var out []byte
	var err error
	switch goos {
	case "darwin":
		out, err = runDialog("osascript", "-e", dialogScript, "--", msg)
	case "linux":
		var name string
		var args []string
		if name, args, err = linuxDialog(msg); err != nil {
			return nil, err
		}
		out, err = runDialog(name, args...)
	default:
		return nil, errors.New("unlocker: no terminal and no GUI prompt on this OS")
	}
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out, []byte("\n")), nil
}

// readPassword prompts on the terminal when stdin is one, else via a GUI dialog; LOCALVAULT_PROMPT=gui|tty forces one.
func readPassword(label string) ([]byte, error) {
	mode := os.Getenv("LOCALVAULT_PROMPT")
	if mode == "" {
		mode = "gui"
		if term.IsTerminal(int(os.Stdin.Fd())) {
			mode = "tty"
		}
	}
	if mode == "gui" {
		return promptGUI(label)
	}
	fmt.Fprint(os.Stderr, label+": ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}
