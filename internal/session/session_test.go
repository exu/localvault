package session

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "session")
	if err := Write(path, []byte("key"), time.Minute); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	dek, exp, err := Read(path)
	if err != nil || !bytes.Equal(dek, []byte("key")) || !exp.After(time.Now()) {
		t.Fatalf("%q %v %v", dek, exp, err)
	}
}

func TestReadMissingExpiredCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session")
	if _, _, err := Read(path); !errors.Is(err, ErrNoSession) {
		t.Fatalf("missing: %v", err)
	}
	Write(path, []byte("k"), -time.Second)
	if _, _, err := Read(path); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expired file not removed")
	}
	os.WriteFile(path, []byte("junk"), 0o600)
	if _, _, err := Read(path); !errors.Is(err, ErrNoSession) {
		t.Fatalf("corrupt: %v", err)
	}
}

func TestClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session")
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	Write(path, []byte("k"), time.Minute)
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path); !errors.Is(err, ErrNoSession) {
		t.Fatalf("got %v", err)
	}
}
