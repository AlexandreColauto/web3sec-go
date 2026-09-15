package sections

// R44A (P1) at the audit sections: the exec section is the headline — it read
// the state twin (state.AllExecs) that folded EVERY ReadDir error into an
// empty list, so `chmod 000 <c>/execs/` certified `audit PASS ... execs=0
// problem(s)` exit 0 while the same campaign refused correctly for findings/
// and chains/ (r43). A section that cannot read its store must refuse; a
// campaign with no execs/ directory (or a genuinely empty one) stays green.
//
// Same treatment for the two other exec readers in this package: the
// sequence-coverage index, and the inconclusive-rung recheck, whose silence
// is reserved for a witness genuinely ABSENT from a store that WAS listed.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/validation"
)

func TestR44aExecsSectionRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r44asec1")
	r43aChmod(t, c.ExecsDir)

	got, err := Execs(c)
	if err == nil {
		t.Fatalf("section 3 certified an unreadable exec store: %v", got)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ExecsDir) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("refusal must name the exec store and the errno: %v", err)
	}
}

// The ENOTDIR shape: execs/ replaced by a regular file.
func TestR44aExecsSectionRefusesNonDirectoryStore(t *testing.T) {
	c := r43aCampaign(t, "C-r44asec2")
	if err := os.RemoveAll(c.ExecsDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.ExecsDir, []byte("not a dir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Execs(c); err == nil {
		t.Fatal("a file where the exec store belongs certified as zero execs")
	}
}

func TestR44aSequenceCoverageRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r44asec3")
	r43aChmod(t, c.ExecsDir)

	if _, err := seqExecIndex(c); err == nil {
		t.Fatal("the sequence-coverage index read an unreadable exec store")
	}
	// The section degrades an error into an ok:false problem entry (its
	// documented convention) rather than raising — the refusal must be in
	// that entry, naming the store, never a silent zero.
	got, err := SequenceCoverage(c)
	if err != nil {
		t.Fatalf("the section degrades, it does not raise: %v", err)
	}
	if ok := objAt(got, "ok"); ok.B {
		t.Fatalf("sequence coverage certified an unreadable exec store: %v", got)
	}
	blob := validation.DumpIndentedASCII(got)
	if !strings.Contains(blob, "cannot be listed") ||
		!strings.Contains(blob, c.ExecsDir) {
		t.Fatalf("the degraded entry must name the exec store: %v", blob)
	}
}

// The inconclusive recheck returns a problem string ("" = nothing wrong). An
// unreadable ledger must not borrow the aged-out witness's silence.
func TestR44aInconclusiveRecheckRefusesUnreadableLedger(t *testing.T) {
	c := r43aCampaign(t, "C-r44asec4")
	r43aChmod(t, c.ExecsDir)

	why := recheckInconclusive(c, nil, "INV-r44a",
		validation.VObj(), validation.VObj(), validation.VObj(),
		"EXEC-r44a", harness.MiniCertora)
	if why == "" || !strings.Contains(why, "the exec ledger cannot be read") ||
		!strings.Contains(why, "INV-r44a") {
		t.Fatalf("the recheck stayed silent about an unreadable ledger: %q", why)
	}
}

// Honest shapes: no execs/ directory, and an empty one, are zero execs.
func TestR44aExecsSectionHonestShapesStayGreen(t *testing.T) {
	absent := r43aCampaign(t, "C-r44asec5")
	if err := os.RemoveAll(absent.ExecsDir); err != nil {
		t.Fatal(err)
	}
	got, err := Execs(absent)
	if err != nil {
		t.Fatalf("an absent exec store is an empty campaign: %v", err)
	}
	if n := objAt(got, "checked"); n.Kind != validation.Int || n.I != 0 {
		t.Fatalf("absent store: checked = %v, want 0", n)
	}
	if ok := objAt(got, "ok"); !ok.B {
		t.Fatalf("absent store: ok = %v, want true", ok)
	}

	empty := r43aCampaign(t, "C-r44asec6")
	if err := os.MkdirAll(empty.ExecsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Execs(empty); err != nil {
		t.Fatalf("an empty exec store is an empty campaign: %v", err)
	}
}
