package cli

import (
	"bytes"
	"strings"
	"testing"
)

func redactAll(t *testing.T, secrets map[string]string, chunks ...string) (string, []string) {
	t.Helper()
	var out bytes.Buffer
	r, skipped := newRedactor(&out, secrets)
	for _, c := range chunks {
		if _, err := r.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String(), skipped
}

func TestRedactBasic(t *testing.T) {
	got, _ := redactAll(t, map[string]string{"TOKEN": "abcd1234"}, "x abcd1234 y abcd1234\n")
	if got != "x [REDACTED:TOKEN] y [REDACTED:TOKEN]\n" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactSplitAcrossWrites(t *testing.T) {
	got, _ := redactAll(t, map[string]string{"TOKEN": "abcd1234"}, "pre abc", "d12", "34 post")
	if got != "pre [REDACTED:TOKEN] post" {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(got, "abcd") {
		t.Fatal("leak")
	}
}

func TestRedactEveryByteChunking(t *testing.T) {
	in := "a abcd1234 b longer-secret-value c abcd1234"
	chunks := strings.Split(in, "")
	got, _ := redactAll(t, map[string]string{"S1": "abcd1234", "S2": "longer-secret-value"}, chunks...)
	if got != "a [REDACTED:S1] b [REDACTED:S2] c [REDACTED:S1]" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactLongestWinsAndTail(t *testing.T) {
	got, _ := redactAll(t, map[string]string{"A": "secret", "B": "secretlong"}, "x secretlong", " tail partial secre")
	if got != "x [REDACTED:B] tail partial secre" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactSkipsShort(t *testing.T) {
	got, skipped := redactAll(t, map[string]string{"K": "ab", "T": "longvalue"}, "ab longvalue")
	if got != "ab [REDACTED:T]" || len(skipped) != 1 || skipped[0] != "K" {
		t.Fatalf("got %q skipped %v", got, skipped)
	}
}

func TestRedactNoSecretsPassesThrough(t *testing.T) {
	got, _ := redactAll(t, map[string]string{}, "hello ", "world")
	if got != "hello world" {
		t.Fatalf("got %q", got)
	}
}
