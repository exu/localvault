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

// runOsascript runs osascript with args; replaced in tests.
var runOsascript = func(args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	c := exec.Command("osascript", args...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		if strings.Contains(errb.String(), "-128") || strings.Contains(errb.String(), "canceled") {
			return nil, ErrCancelled
		}
		return nil, fmt.Errorf("unlocker: dialog failed: %s", strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func promptGUI(label string) ([]byte, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("unlocker: no terminal and no GUI prompt on this OS")
	}
	msg := strings.TrimSpace(PromptMessage + "\n\n" + label)
	out, err := runOsascript("-e", dialogScript, msg)
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
