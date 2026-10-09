package unlocker

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"
)

// fakePinentry serves the Assuan protocol, answering GETPIN with reply, and records commands.
func fakePinentry(t *testing.T, reply string) (io.ReadWriter, *[]string) {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	var cmds []string
	go func() {
		w := sw
		io.WriteString(w, "OK Pleased to meet you\n")
		sc := bufio.NewScanner(sr)
		for sc.Scan() {
			line := sc.Text()
			cmds = append(cmds, line)
			if line == "BYE" {
				io.WriteString(w, "OK closing connection\n")
				w.Close()
				return
			}
			if line == "GETPIN" {
				io.WriteString(w, reply)
				continue
			}
			io.WriteString(w, "OK\n")
		}
	}()
	return struct {
		io.Reader
		io.Writer
	}{cr, cw}, &cmds
}

func TestPinentryExchangeSuccess(t *testing.T) {
	rw, cmds := fakePinentry(t, "D p%25ss\nOK\n")
	pw, err := pinentryExchange(rw, "claude requests: get X\nsession 15m", "Vault password:")
	if err != nil || string(pw) != "p%ss" {
		t.Fatalf("%q %v", pw, err)
	}
	joined := strings.Join(*cmds, "|")
	for _, want := range []string{"SETTITLE localvault", "SETDESC claude requests: get X%0Asession 15m", "SETPROMPT Vault password:", "SETTIMEOUT 60", "GETPIN"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %q", want, joined)
		}
	}
}

func TestPinentryExchangeCancelAndTimeout(t *testing.T) {
	for _, reply := range []string{
		"ERR 83886179 Operation cancelled <Pinentry>\n",
		"ERR 83886142 Timeout <Pinentry>\n",
	} {
		rw, _ := fakePinentry(t, reply)
		if _, err := pinentryExchange(rw, "d", "p"); !errors.Is(err, ErrCancelled) {
			t.Fatalf("%q: got %v", reply, err)
		}
	}
	rw, _ := fakePinentry(t, "ERR 1 boom\n")
	if _, err := pinentryExchange(rw, "d", "p"); err == nil || errors.Is(err, ErrCancelled) {
		t.Fatalf("other error: %v", err)
	}
}

func TestPromptGUILinuxPrefersPinentry(t *testing.T) {
	stubDialog(t, "linux", "pinentry-qt", "zenity")
	var gotProg, gotDesc, gotPrompt string
	runPinentry = func(prog, desc, prompt string) ([]byte, error) {
		gotProg, gotDesc, gotPrompt = prog, desc, prompt
		return []byte("pw"), nil
	}
	PromptMessage = "who wants what"
	defer func() { PromptMessage = "" }()
	pw, err := promptGUI("Vault password")
	if err != nil || string(pw) != "pw" || gotProg != "pinentry-qt" || gotDesc != "who wants what" || gotPrompt != "Vault password:" {
		t.Fatalf("%q %v %q %q %q", pw, err, gotProg, gotDesc, gotPrompt)
	}
}

type fakeEntry string

func (f fakeEntry) Name() string               { return string(f) }
func (f fakeEntry) IsDir() bool                { return false }
func (f fakeEntry) Type() fs.FileMode          { return 0 }
func (f fakeEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestEnsureDisplayEnvFindsWayland(t *testing.T) {
	stubDialog(t, "linux")
	getenv = func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return "/run/user/1000"
		}
		return ""
	}
	readDir = func(string) ([]fs.DirEntry, error) {
		return []fs.DirEntry{fakeEntry("bus"), fakeEntry("wayland-1.lock"), fakeEntry("wayland-1")}, nil
	}
	set := map[string]string{}
	origSet := setenv
	setenv = func(k, v string) error { set[k] = v; return nil }
	defer func() { setenv = origSet }()

	if !ensureDisplayEnv() || set["WAYLAND_DISPLAY"] != "wayland-1" || set["XDG_RUNTIME_DIR"] != "/run/user/1000" {
		t.Fatalf("env %v", set)
	}
}

func TestEnsureDisplayEnvNone(t *testing.T) {
	stubDialog(t, "linux")
	getenv = func(string) string { return "" }
	readDir = func(string) ([]fs.DirEntry, error) { return nil, errors.New("no dir") }
	if ensureDisplayEnv() {
		t.Fatal("expected no display")
	}
}
