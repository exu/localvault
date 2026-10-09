package unlocker

import (
	"errors"
	"runtime"
	"testing"
)

func TestPromptGUI(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	orig := runOsascript
	defer func() { runOsascript = orig }()
	PromptMessage = "claude requests: get X"
	defer func() { PromptMessage = "" }()

	var gotArgs []string
	runOsascript = func(args ...string) ([]byte, error) {
		gotArgs = args
		return []byte("s3cret\n"), nil
	}
	pw, err := promptGUI("Vault password")
	if err != nil || string(pw) != "s3cret" {
		t.Fatalf("%q %v", pw, err)
	}
	if gotArgs[len(gotArgs)-1] != "claude requests: get X\n\nVault password" {
		t.Fatalf("message %q", gotArgs[len(gotArgs)-1])
	}

	runOsascript = func(...string) ([]byte, error) { return nil, ErrCancelled }
	if _, err := promptGUI("x"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("got %v", err)
	}
}

func TestReadPasswordForcedGUI(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	orig := runOsascript
	defer func() { runOsascript = orig }()
	runOsascript = func(...string) ([]byte, error) { return []byte("pw\n"), nil }
	t.Setenv("LOCALVAULT_PROMPT", "gui")
	pw, err := readPassword("x")
	if err != nil || string(pw) != "pw" {
		t.Fatalf("%q %v", pw, err)
	}
}
