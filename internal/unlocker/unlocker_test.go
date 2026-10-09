package unlocker

import (
	"bytes"
	"errors"
	"testing"
)

var fastParams = Params{Time: 1, Memory: 8, Threads: 1}

func pw(s string) *Password {
	return &Password{Prompt: func() ([]byte, error) { return []byte(s), nil }, Params: fastParams}
}

func TestPasswordRoundTrip(t *testing.T) {
	dek := bytes.Repeat([]byte{7}, 32)
	blob, err := pw("hunter2").Enroll(dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pw("hunter2").Unlock(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("dek mismatch")
	}
}

func TestPasswordWrong(t *testing.T) {
	blob, _ := pw("right").Enroll(bytes.Repeat([]byte{1}, 32))
	if _, err := pw("wrong").Unlock(blob); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("got %v", err)
	}
}

func TestPasswordEmptyAndCorrupt(t *testing.T) {
	if _, err := pw("").Enroll(make([]byte, 32)); err == nil {
		t.Fatal("expected empty password error")
	}
	if _, err := pw("x").Unlock([]byte("not json")); err == nil {
		t.Fatal("expected corrupt error")
	}
	if _, err := pw("x").Unlock([]byte(`{"salt":"AA==","nonce":"AA=="}`)); err == nil {
		t.Fatal("expected bad nonce error")
	}
}

func TestPasswordPromptError(t *testing.T) {
	boom := errors.New("boom")
	p := &Password{Prompt: func() ([]byte, error) { return nil, boom }, Params: fastParams}
	if _, err := p.Enroll(make([]byte, 32)); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestRegistry(t *testing.T) {
	u, err := Get("password")
	if err != nil || u.Name() != "password" {
		t.Fatalf("%v %v", u, err)
	}
	if _, err := Get("nope"); err == nil {
		t.Fatal("expected unknown error")
	}
	if len(Names()) == 0 {
		t.Fatal("no names")
	}
}

func TestPasswordConfirm(t *testing.T) {
	p := pw("a")
	p.Confirm = func() ([]byte, error) { return []byte("b"), nil }
	if _, err := p.Enroll(make([]byte, 32)); err == nil {
		t.Fatal("expected mismatch error")
	}
	p.Confirm = func() ([]byte, error) { return []byte("a"), nil }
	if _, err := p.Enroll(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}
