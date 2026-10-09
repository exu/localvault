package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/exu/localvault/internal/unlocker"
)

type env struct {
	t   *testing.T
	app *App
	pw  string
	in  string
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, pw: "pw1"}
	e.app = &App{Dir: t.TempDir()}
	unlocker.Register(&unlocker.Password{
		Prompt:  func() ([]byte, error) { return []byte(e.pw), nil },
		Confirm: func() ([]byte, error) { return []byte(e.pw), nil },
		Params:  unlocker.Params{Time: 1, Memory: 8, Threads: 1},
	})
	return e
}

func (e *env) run(args ...string) (string, error) {
	var out bytes.Buffer
	e.app.In = strings.NewReader(e.in)
	e.app.Out = &out
	e.app.Err = &out
	cmd := e.app.NewRoot()
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func (e *env) must(args ...string) string {
	e.t.Helper()
	out, err := e.run(args...)
	if err != nil {
		e.t.Fatalf("%v: %v", args, err)
	}
	return out
}

func TestFlow(t *testing.T) {
	e := newEnv(t)
	if _, err := e.run("get", "A"); err == nil || !strings.Contains(err.Error(), "configure") {
		t.Fatalf("no vault: %v", err)
	}
	e.must("configure")

	if _, err := e.run("set", "A=1", "--no-prompt"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked set: %v", err)
	}
	if out := e.must("status"); !strings.Contains(out, "locked") {
		t.Fatalf("status %q", out)
	}

	e.must("unlock")
	if out := e.must("status"); !strings.Contains(out, "unlocked") {
		t.Fatalf("status %q", out)
	}
	e.must("set", "A=1", "B=two=words")
	e.in = "from stdin\n"
	e.must("set", "C=-")
	for k, want := range map[string]string{"A": "1", "B": "two=words", "C": "from stdin"} {
		if got := e.must("get", k); got != want+"\n" {
			t.Fatalf("get %s = %q want %q", k, got, want)
		}
	}
	if _, err := e.run("get", "MISSING"); err == nil {
		t.Fatal("expected not found")
	}

	e.must("lock")
	if _, err := e.run("get", "A", "--no-prompt"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("after lock: %v", err)
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	e := newEnv(t)
	e.must("configure")
	e.pw = "bad"
	if _, err := e.run("unlock"); err == nil {
		t.Fatal("expected wrong password error")
	}
	if out := e.must("status"); !strings.Contains(out, "locked") {
		t.Fatalf("status %q", out)
	}
}

func TestSetInvalidArgsAndTTL(t *testing.T) {
	e := newEnv(t)
	e.must("configure")
	e.must("unlock", "--ttl", "1m")
	for _, arg := range []string{"NOEQUALS", "=v"} {
		if _, err := e.run("set", arg); err == nil {
			t.Fatalf("expected error for %q", arg)
		}
	}
	if _, err := e.run("unlock", "--ttl", "0s"); err == nil {
		t.Fatal("expected ttl error")
	}
}

func TestConfigureExistingChangesPassword(t *testing.T) {
	e := newEnv(t)
	e.must("configure")
	e.must("unlock")
	e.must("set", "A=1")
	e.must("lock")

	// existing vault: authenticate with old password, then enroll the new one
	e.pw = "pw1"
	calls := 0
	unlocker.Register(&unlocker.Password{
		Prompt: func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte("pw1"), nil
			}
			return []byte("pw2"), nil
		},
		Confirm: func() ([]byte, error) { return []byte("pw2"), nil },
		Params:  unlocker.Params{Time: 1, Memory: 8, Threads: 1},
	})
	e.must("configure")

	e.pw = "pw2"
	unlocker.Register(&unlocker.Password{
		Prompt: func() ([]byte, error) { return []byte("pw2"), nil },
		Params: unlocker.Params{Time: 1, Memory: 8, Threads: 1},
	})
	e.must("unlock")
	if got := e.must("get", "A"); got != "1\n" {
		t.Fatalf("secret lost after re-enroll: %q", got)
	}
}

func TestUnlockNotEnrolledAndUnknownUnlocker(t *testing.T) {
	e := newEnv(t)
	e.must("configure")
	if _, err := e.run("unlock", "--with", "touchid"); err == nil {
		t.Fatal("expected not enrolled")
	}
	if _, err := e.run("configure", "--with", "nope"); err == nil {
		t.Fatal("expected unknown unlocker")
	}
}

func TestListDeleteRun(t *testing.T) {
	e := newEnv(t)
	e.must("configure")
	e.must("unlock")
	e.must("set", "B=2", "A=hello world")
	if got := e.must("list"); got != "A\nB\n" {
		t.Fatalf("list %q", got)
	}
	if got := e.must("run", `printf '%s|%s' "$env[A]" $env[B]`); got != "hello world|2" {
		t.Fatalf("run %q", got)
	}
	if _, err := e.run("run", "echo $env[NOPE]"); err == nil {
		t.Fatal("expected missing key error")
	}
	e.must("delete", "A")
	if got := e.must("list"); got != "B\n" {
		t.Fatalf("list after delete %q", got)
	}
	if _, err := e.run("delete", "A"); err == nil {
		t.Fatal("expected not found")
	}
}

func TestAutoUnlockOnLocked(t *testing.T) {
	e := newEnv(t)
	e.must("configure")
	e.must("unlock")
	e.must("set", "A=1")
	e.must("lock")

	if _, err := e.run("get", "A", "--no-prompt"); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("no-prompt: %v", err)
	}
	if got := e.must("get", "A"); got != "1\n" {
		t.Fatalf("auto unlock get %q", got)
	}
	if out := e.must("status"); !strings.Contains(out, "unlocked") {
		t.Fatalf("session not started: %q", out)
	}

	e.pw = "wrong"
	e.must("lock")
	if _, err := e.run("get", "A"); err == nil {
		t.Fatal("expected wrong password error")
	}
}

func TestDescribeHidesValues(t *testing.T) {
	e := newEnv(t)
	root := e.app.NewRoot()
	setCmd, _, _ := root.Find([]string{"set"})
	if got := describe(setCmd, []string{"A=topsecret", "B=x"}); got != "set A, B" {
		t.Fatalf("describe %q", got)
	}
	getCmd, _, _ := root.Find([]string{"get"})
	if got := describe(getCmd, []string{"TOKEN"}); got != "get TOKEN" {
		t.Fatalf("describe %q", got)
	}
	runCmd, _, _ := root.Find([]string{"run"})
	if got := describe(runCmd, []string{strings.Repeat("x", 100)}); len(got) != len("run ")+63 {
		t.Fatalf("run not truncated: %q", got)
	}
}
