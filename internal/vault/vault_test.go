package vault

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	dek, _ := NewDEK()
	secrets := map[string]string{"A": "1", "B": "two words"}
	f, err := Seal(dek, secrets, []Entry{{Name: "password", Blob: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.Open(dek)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, secrets) {
		t.Fatalf("got %v want %v", got, secrets)
	}
}

func TestOpenWrongKeyAndTamper(t *testing.T) {
	dek, _ := NewDEK()
	other, _ := NewDEK()
	f, _ := Seal(dek, map[string]string{"A": "1"}, nil)

	if _, err := f.Open(other); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: got %v", err)
	}
	f.Ciphertext[0] ^= 0xff
	if _, err := f.Open(dek); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tamper: got %v", err)
	}
}

func TestOpenUnsupportedVersion(t *testing.T) {
	dek, _ := NewDEK()
	f, _ := Seal(dek, nil, nil)
	f.Version = 99
	if _, err := f.Open(dek); err == nil {
		t.Fatal("expected version error")
	}
}

func TestSetEntryUpsert(t *testing.T) {
	f := &File{}
	f.SetEntry(Entry{Name: "a", Blob: []byte("1")})
	f.SetEntry(Entry{Name: "b", Blob: []byte("2")})
	f.SetEntry(Entry{Name: "a", Blob: []byte("3")})
	if len(f.Unlockers) != 2 {
		t.Fatalf("len %d", len(f.Unlockers))
	}
	e, ok := f.Entry("a")
	if !ok || string(e.Blob) != "3" {
		t.Fatalf("entry %v %v", e, ok)
	}
	if _, ok := f.Entry("zzz"); ok {
		t.Fatal("unexpected entry")
	}
}

func TestSaveLoad(t *testing.T) {
	dek, _ := NewDEK()
	f, _ := Seal(dek, map[string]string{"K": "v"}, []Entry{{Name: "password", Blob: []byte("b")}})
	path := filepath.Join(t.TempDir(), "sub", "vault.lv")
	if err := Save(path, f); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := got.Open(dek)
	if err != nil || secrets["K"] != "v" {
		t.Fatalf("%v %v", secrets, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
}
