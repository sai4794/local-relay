package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: a second YAML document after "---" must be rejected, even when
// the trailing document is malformed. The previous "err == nil && extra !=
// nil" guard accepted an unscannable second document (Decode returns a syntax
// error AND a nil extra), silently ignoring operator-appended content.
func TestRegression_LoadRejectsSecondDocument(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Malformed second document: must fail (previously accepted with err==nil path).
	bad := "server:\n  http: \"127.0.0.1:18080\"\n---\n: bad: [\n"
	if _, err := Load(write(t, bad)); err == nil {
		t.Error("Load accepted a malformed second YAML document; want rejection")
	}

	// Well-formed non-empty second document: must fail.
	dup := "server:\n  http: \"127.0.0.1:18080\"\n---\nserver:\n  http: \"127.0.0.1:19090\"\n"
	if _, err := Load(write(t, dup)); err == nil {
		t.Error("Load accepted two YAML documents; want rejection")
	}

	// Empty trailing document (trailing "---" with nothing after) stays valid:
	// dec.Decode returns io.EOF (err != nil), so single-document configs keep
	// loading unchanged.
	trailing := "server:\n  http: \"127.0.0.1:18080\"\n---\n"
	if _, err := Load(write(t, trailing)); err != nil {
		t.Errorf("Load rejected a trailing empty document: %v (want acceptance)", err)
	}

	// Plain single-document config stays valid.
	single := "server:\n  http: \"127.0.0.1:18080\"\n"
	if _, err := Load(write(t, single)); err != nil {
		t.Errorf("Load rejected a valid single-document config: %v", err)
	}
}
