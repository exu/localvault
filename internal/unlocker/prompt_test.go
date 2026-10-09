package unlocker

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func stubDialog(t *testing.T, os string, programs ...string) *[]string {
	t.Helper()
	origGoos, origLook, origRun, origEnv, origDir, origPin := goos, lookPath, runDialog, getenv, readDir, runPinentry
	t.Cleanup(func() {
		goos, lookPath, runDialog, getenv, readDir, runPinentry = origGoos, origLook, origRun, origEnv, origDir, origPin
	})
	goos = os
	getenv = func(k string) string {
		if k == "DISPLAY" {
			return ":0"
		}
		return ""
	}
	readDir = func(string) ([]fs.DirEntry, error) { return nil, errors.New("no dir") }
	lookPath = func(name string) (string, error) {
		for _, p := range programs {
			if p == name {
				return "/usr/bin/" + name, nil
			}
		}
		return "", errors.New("not found")
	}
	var got []string
	runDialog = func(name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte("s3cret\n"), nil
	}
	return &got
}

func TestPromptGUIDarwin(t *testing.T) {
	got := stubDialog(t, "darwin")
	PromptMessage = "claude requests: get X"
	defer func() { PromptMessage = "" }()

	pw, err := promptGUI("Vault password")
	if err != nil || string(pw) != "s3cret" {
		t.Fatalf("%q %v", pw, err)
	}
	args := *got
	if args[0] != "osascript" || args[len(args)-2] != "--" {
		t.Fatalf("args %q", args)
	}
	if args[len(args)-1] != "claude requests: get X\n\nVault password" {
		t.Fatalf("message %q", args[len(args)-1])
	}

	runDialog = func(string, ...string) ([]byte, error) { return nil, ErrCancelled }
	if _, err := promptGUI("x"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("got %v", err)
	}
}

func TestPromptGUILinuxBackends(t *testing.T) {
	for _, tc := range []struct {
		programs []string
		want     string
	}{
		{[]string{"zenity", "kdialog"}, "zenity"},
		{[]string{"kdialog"}, "kdialog"},
		{[]string{"yad"}, "yad"},
	} {
		got := stubDialog(t, "linux", tc.programs...)
		pw, err := promptGUI("Vault password")
		if err != nil || string(pw) != "s3cret" {
			t.Fatalf("%s: %q %v", tc.want, pw, err)
		}
		if (*got)[0] != tc.want {
			t.Fatalf("backend %q want %q", (*got)[0], tc.want)
		}
	}
}

func TestPromptGUILinuxErrors(t *testing.T) {
	stubDialog(t, "linux")
	if _, err := promptGUI("x"); err == nil || !strings.Contains(err.Error(), "pinentry") {
		t.Fatalf("no program: %v", err)
	}
	getenv = func(string) string { return "" }
	if _, err := promptGUI("x"); err == nil || !strings.Contains(err.Error(), "display") {
		t.Fatalf("no display: %v", err)
	}
	goos = "windows"
	if _, err := promptGUI("x"); err == nil {
		t.Fatal("expected unsupported OS error")
	}
}

func TestReadPasswordForcedGUI(t *testing.T) {
	stubDialog(t, "darwin")
	t.Setenv("LOCALVAULT_PROMPT", "gui")
	pw, err := readPassword("x")
	if err != nil || string(pw) != "s3cret" {
		t.Fatalf("%q %v", pw, err)
	}
}
