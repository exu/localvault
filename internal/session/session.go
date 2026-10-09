// Package session stores the unlocked DEK in a short-lived 0600 file.
package session

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/exu/localvault/internal/fsutil"
)

var (
	ErrNoSession = errors.New("session: locked")
	ErrExpired   = errors.New("session: expired")
)

type data struct {
	DEK     []byte `json:"dek"`
	Expires int64  `json:"expires"`
}

// Write stores dek at path, valid for ttl.
func Write(path string, dek []byte, ttl time.Duration) error {
	b, err := json.Marshal(data{DEK: dek, Expires: time.Now().Add(ttl).UnixNano()})
	if err != nil {
		return err
	}
	return fsutil.WriteAtomic(path, b)
}

// Read returns the DEK and its expiry; an expired session file is removed.
func Read(path string) ([]byte, time.Time, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, time.Time{}, ErrNoSession
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	var d data
	if err := json.Unmarshal(b, &d); err != nil || len(d.DEK) == 0 {
		Clear(path)
		return nil, time.Time{}, ErrNoSession
	}
	exp := time.Unix(0, d.Expires)
	if !time.Now().Before(exp) {
		Clear(path)
		return nil, time.Time{}, ErrExpired
	}
	return d.DEK, exp, nil
}

// Clear removes the session file if present.
func Clear(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
