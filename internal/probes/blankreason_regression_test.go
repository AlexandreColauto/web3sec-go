package probes

import (
	"strings"
	"testing"

	"websec/internal/state"
)

// The blank-attestation reason is a minimum on CHARACTERS, not bytes. A
// multibyte reason that is short in characters but long in bytes (e.g. 5 CJK
// chars = 15 bytes) must be REJECTED as too short. The pre-fix len() counted
// bytes, so it passed the >= 10 check and fell through to the surface error.
func TestBlankReasonMinCountsCharsNotBytes(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Blank Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// 5 CJK chars: 5 runes (< 10) but 15 bytes (>= 10).
	reason := "审计理由短"
	if _, err := SetBlank(c, "liveness", "some-blind-key", reason, "op"); err == nil {
		t.Fatal("a 5-char reason must be rejected (below the 10-char minimum)")
	} else if !strings.Contains(err.Error(), "written reason") {
		t.Errorf("error = %q, want the char-count reason check (got a different error, e.g. the surface check)", err.Error())
	}

	// A reason that is 10+ CHARACTERS (even if short in bytes) must pass the
	// reason check — it then fails later on the (absent) surface, not on the
	// reason length.
	if _, err := SetBlank(c, "liveness", "some-blind-key", "ten char ok reason", "op"); err == nil {
		t.Fatal("expected a later error (no probe surface), got nil")
	} else if strings.Contains(err.Error(), "written reason") {
		t.Errorf("a 10+ char reason must pass the length check, got: %q", err.Error())
	}
}
