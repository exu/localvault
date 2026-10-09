package cli

import (
	"bytes"
	"io"
	"sort"
)

// minRedactLen is the shortest secret value that gets scrubbed; shorter ones would mangle output.
const minRedactLen = 4

type redactor struct {
	w       io.Writer
	secrets []secretVal
	maxLen  int
	buf     []byte
}

type secretVal struct {
	name string
	val  []byte
}

// newRedactor returns a writer that replaces any secret value in the stream with [REDACTED:NAME], plus the names skipped for being too short.
func newRedactor(w io.Writer, secrets map[string]string) (*redactor, []string) {
	r := &redactor{w: w}
	var skipped []string
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := secrets[n]
		if len(v) < minRedactLen {
			skipped = append(skipped, n)
			continue
		}
		r.secrets = append(r.secrets, secretVal{n, []byte(v)})
		if len(v) > r.maxLen {
			r.maxLen = len(v)
		}
	}
	return r, skipped
}

// next finds the earliest match in buf, preferring the longest on ties.
func (r *redactor) next() (idx int, s secretVal) {
	idx = -1
	for _, c := range r.secrets {
		i := bytes.Index(r.buf, c.val)
		if i < 0 {
			continue
		}
		if idx < 0 || i < idx || (i == idx && len(c.val) > len(s.val)) {
			idx, s = i, c
		}
	}
	return idx, s
}

func (r *redactor) drain(final bool) error {
	for {
		i, s := r.next()
		if i < 0 {
			break
		}
		if _, err := r.w.Write(append(append([]byte{}, r.buf[:i]...), "[REDACTED:"+s.name+"]"...)); err != nil {
			return err
		}
		r.buf = r.buf[i+len(s.val):]
	}
	safe := len(r.buf)
	if !final && r.maxLen > 0 {
		safe -= r.maxLen - 1
	} else if !final {
		safe = len(r.buf)
	}
	if safe > 0 {
		if _, err := r.w.Write(r.buf[:safe]); err != nil {
			return err
		}
		r.buf = append(r.buf[:0], r.buf[safe:]...)
	}
	return nil
}

func (r *redactor) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	if err := r.drain(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes the held-back tail.
func (r *redactor) Close() error { return r.drain(true) }
