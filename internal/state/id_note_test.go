package state

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/validation"
)

var nowIsoRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$`)

// TestNowIso: UTC, fixed 6-digit microseconds, +00:00 (never Z).
func TestNowIso(t *testing.T) {
	for i := 0; i < 5; i++ {
		if !nowIsoRe.MatchString(nowIso()) {
			t.Errorf("nowIso format: %q", nowIso())
		}
	}
}

// TestNewId: prefix-hex shape, requested length, uuid4 version nibble.
func TestNewId(t *testing.T) {
	re10 := regexp.MustCompile(`^C-[0-9a-f]{10}$`)
	re13 := regexp.MustCompile(`^C-[0-9a-f]{12}4$`)
	if !re10.MatchString(newId("C", 10)) {
		t.Errorf("newId C 10: %q", newId("C", 10))
	}
	if got := newId("F", 0); got != "F-" {
		t.Errorf("n=0: %q", got)
	}
	for i := 0; i < 50; i++ {
		id := newId("C", 13)
		if !re13.MatchString(id) {
			t.Errorf("uuid4 version nibble: %q", id)
		}
	}
	// 1000 draws must not collide at n=12 (6^12 hex space)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newId("C", 12)
		if seen[id] {
			t.Fatalf("collision: %q", id)
		}
		seen[id] = true
	}
}

// TestCapNote: None -> "", passthrough, sorted dict serialization,
// exact-cap boundary, truncation marker.
func TestCapNote(t *testing.T) {
	if got := capNote(validation.VNull()); got != "" {
		t.Errorf("null: %q", got)
	}
	if got := capNote(validation.VStr("hello")); got != "hello" {
		t.Errorf("short str: %q", got)
	}
	d := validation.VObj(
		kv("b", validation.VInt(2)),
		kv("a", validation.VStr("x")),
	)
	if got := capNote(d); got != `{"a": "x", "b": 2}` {
		t.Errorf("dict sorted: %q", got)
	}
	exact := strings.Repeat("a", 4096)
	if got := capNote(validation.VStr(exact)); got != exact {
		t.Errorf("exact cap must pass through (len=%d)", len(got))
	}
	long := strings.Repeat("b", 4100)
	capped := capNote(validation.VStr(long))
	want := strings.Repeat("b", 4096) +
		" \u2026[truncated 4 chars \u2014 full content must live in an artifact, not a stage note]"
	if capped != want {
		t.Errorf("truncation:\n got tail %q\nwant tail %q",
			capped[len(capped)-60:], want[len(want)-60:])
	}
}

// TestSha256Helpers re-pin the known vector at the state package boundary.
func TestSha256Helpers(t *testing.T) {
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := validation.Sha256Hex([]byte("abc")); got != want {
		t.Errorf("Sha256Hex: %q", got)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "s.bin")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := validation.Sha256File(p); err != nil || got != want {
		t.Errorf("Sha256File: %q %v", got, err)
	}
}
