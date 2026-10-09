package unlocker

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

// ErrBadPassword is returned when the password cannot unwrap the DEK.
var ErrBadPassword = errors.New("unlocker: wrong password")

// Params are argon2id cost parameters, stored in the blob so they can evolve.
type Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

// DefaultParams are the argon2id parameters used for new enrollments.
var DefaultParams = Params{Time: 3, Memory: 64 * 1024, Threads: 4}

type passwordBlob struct {
	Params
	Salt    []byte `json:"salt"`
	Nonce   []byte `json:"nonce"`
	Wrapped []byte `json:"wrapped"`
}

// Password wraps the DEK with a key derived from a user password via argon2id.
type Password struct {
	// Prompt returns the password, from a terminal by default.
	Prompt func() ([]byte, error)
	// Confirm, when set, is asked on Enroll and must match Prompt.
	Confirm func() ([]byte, error)
	Params  Params
}

// NewPassword returns a Password unlocker that prompts on the terminal.
func NewPassword() *Password {
	return &Password{
		Prompt:  func() ([]byte, error) { return promptTerminal("Password: ") },
		Confirm: func() ([]byte, error) { return promptTerminal("Confirm password: ") },
		Params:  DefaultParams,
	}
}

func promptTerminal(label string) ([]byte, error) {
	fmt.Fprint(os.Stderr, label)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return pw, err
}

func (p *Password) Name() string    { return "password" }
func (p *Password) Available() bool { return p.Prompt != nil }

func (p *Password) kek(pw, salt []byte, prm Params) []byte {
	return argon2.IDKey(pw, salt, prm.Time, prm.Memory, prm.Threads, chacha20poly1305.KeySize)
}

func (p *Password) Enroll(dek []byte) ([]byte, error) {
	pw, err := p.Prompt()
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, errors.New("unlocker: empty password")
	}
	if p.Confirm != nil {
		again, err := p.Confirm()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pw, again) {
			return nil, errors.New("unlocker: passwords do not match")
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(p.kek(pw, salt, p.Params))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.Marshal(passwordBlob{
		Params:  p.Params,
		Salt:    salt,
		Nonce:   nonce,
		Wrapped: aead.Seal(nil, nonce, dek, nil),
	})
}

func (p *Password) Unlock(blob []byte) ([]byte, error) {
	var b passwordBlob
	if err := json.Unmarshal(blob, &b); err != nil {
		return nil, fmt.Errorf("unlocker: corrupt password blob: %w", err)
	}
	if b.Time == 0 || b.Threads == 0 || b.Memory < 8*uint32(b.Threads) {
		return nil, errors.New("unlocker: corrupt password blob")
	}
	pw, err := p.Prompt()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(p.kek(pw, b.Salt, b.Params))
	if err != nil {
		return nil, err
	}
	if len(b.Nonce) != aead.NonceSize() {
		return nil, errors.New("unlocker: corrupt password blob")
	}
	dek, err := aead.Open(nil, b.Nonce, b.Wrapped, nil)
	if err != nil {
		return nil, ErrBadPassword
	}
	return dek, nil
}

func init() { Register(NewPassword()) }
