// Package vault implements the encrypted vault file format.
package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/exu/localvault/internal/fsutil"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Version 2 authenticates the unlocker list; version 1 files still open and upgrade on next save.
	Version       = 2
	legacyVersion = 1
	DEKSize       = chacha20poly1305.KeySize
)

var ErrDecrypt = errors.New("vault: decryption failed")

// Entry is one unlocker's wrapped copy of the DEK.
type Entry struct {
	Name string `json:"name"`
	Blob []byte `json:"blob"`
}

// File is the on-disk vault: unlocker entries plus the sealed secrets.
type File struct {
	Version    int     `json:"version"`
	Unlockers  []Entry `json:"unlockers"`
	Nonce      []byte  `json:"nonce"`
	Ciphertext []byte  `json:"ciphertext"`
}

// NewDEK returns a fresh random data encryption key.
func NewDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// aad binds the format version and the unlocker list to the ciphertext.
func aad(version int, entries []Entry) ([]byte, error) {
	if version == legacyVersion {
		return []byte{legacyVersion}, nil
	}
	h, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(h)
	return append([]byte{byte(version)}, sum[:]...), nil
}

// Seal encrypts secrets with dek and returns a File carrying the given unlocker entries.
func Seal(dek []byte, secrets map[string]string, entries []Entry) (*File, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ad, err := aad(Version, entries)
	if err != nil {
		return nil, err
	}
	return &File{
		Version:    Version,
		Unlockers:  entries,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plain, ad),
	}, nil
}

// Open decrypts the secrets with dek.
func (f *File) Open(dek []byte) (map[string]string, error) {
	if f.Version != Version && f.Version != legacyVersion {
		return nil, fmt.Errorf("vault: unsupported version %d", f.Version)
	}
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}
	if len(f.Nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	ad, err := aad(f.Version, f.Unlockers)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, f.Nonce, f.Ciphertext, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	secrets := map[string]string{}
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

// Entry returns the unlocker entry with the given name.
func (f *File) Entry(name string) (Entry, bool) {
	for _, e := range f.Unlockers {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

// SetEntry adds or replaces the unlocker entry with e.Name.
func (f *File) SetEntry(e Entry) {
	for i := range f.Unlockers {
		if f.Unlockers[i].Name == e.Name {
			f.Unlockers[i] = e
			return
		}
	}
	f.Unlockers = append(f.Unlockers, e)
}

// Load reads a vault file from path.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("vault: corrupt file: %w", err)
	}
	return &f, nil
}

// Save atomically writes the vault file to path with mode 0600.
func Save(path string, f *File) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(path, b)
}
