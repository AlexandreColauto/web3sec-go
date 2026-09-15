package sections

// R43A (P1) at the audit sections. `audit` is the surface that is supposed to
// catch a broken campaign: with findings/ unreadable it used to report
// `findings=0 problem(s)` and PASS, and with chains/ unreadable the projection
// lost the premise of both its directions and PASSed too. A section that
// cannot read its store must refuse (the audit surfaces the error), while a
// campaign that simply has no new directory stays green.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func r43aCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r43a", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	return c
}

func r43aChmod(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skipf("cannot create an unreadable directory here (%s stayed readable)", dir)
	}
}

// TestR43aFindingsSectionRefusesUnreadableStore: section 4 must not answer
// {checked:0, ok:true} for a store it could not read — that is the "audit
// PASS: findings=0 problem(s)" the P1 repro captured.
func TestR43aFindingsSectionRefusesUnreadableStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43asec1")
	r43aChmod(t, c.FindingsDir)

	sec, err := Findings(c)
	if err == nil {
		t.Fatalf("Findings on an unreadable store returned %v with no error", sec)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.FindingsDir) {
		t.Fatalf("refusal must name the findings store: %v", err)
	}
}

func TestR43aFindingsSectionAbsentStoreIsGreen(t *testing.T) {
	c := r43aCampaign(t, "C-r43asec2")
	if err := os.RemoveAll(c.FindingsDir); err != nil {
		t.Fatal(err)
	}
	sec, err := Findings(c)
	if err != nil {
		t.Fatalf("an absent findings store is an empty campaign: %v", err)
	}
	if n := objAt(sec, "checked").I; n != 0 {
		t.Fatalf("checked = %d, want 0", n)
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Fatalf("ok = %v, want true", ok)
	}
}

func TestR43aFindingsSectionEmptyStoreIsGreen(t *testing.T) {
	c := r43aCampaign(t, "C-r43asec3")
	sec, err := Findings(c)
	if err != nil {
		t.Fatalf("a genuinely empty findings store: %v", err)
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Fatalf("ok = %v, want true", ok)
	}
}

// TestR43aUnpriceableSectionPropagatesTheFindingsRefusal: section 14 reads the
// same files; it used to check zero findings when the store was unreadable.
func TestR43aUnpriceableSectionPropagatesTheFindingsRefusal(t *testing.T) {
	c := r43aCampaign(t, "C-r43asec4")
	r43aChmod(t, c.FindingsDir)

	if _, err := Unpriceable(c); err == nil {
		t.Fatal("Unpriceable swallowed the read failure")
	} else if !strings.Contains(err.Error(), "cannot be listed") {
		t.Fatalf("refusal must name the store: %v", err)
	}
}

// TestR43aProjectionRefusesUnreadableChainStore: the chains/ projection is
// PRESENCE-GATED on the document list, so an unreadable directory made both
// directions (event->doc, doc->event) vacuous. It must refuse.
func TestR43aProjectionRefusesUnreadableChainStore(t *testing.T) {
	c := r43aCampaign(t, "C-r43asec5")
	r43aChmod(t, c.ChainsDir)

	sec, err := Projection(c)
	if err == nil {
		t.Fatalf("Projection on an unreadable chain store returned %v with no error", sec)
	}
	if !strings.Contains(err.Error(), "cannot be listed") ||
		!strings.Contains(err.Error(), c.ChainsDir) {
		t.Fatalf("refusal must name the chain store: %v", err)
	}
}

func TestR43aProjectionAbsentChainStoreIsGreen(t *testing.T) {
	c := r43aCampaign(t, "C-r43asec6")
	if err := os.RemoveAll(c.ChainsDir); err != nil {
		t.Fatal(err)
	}
	sec, err := Projection(c)
	if err != nil {
		t.Fatalf("an absent chains store is an empty campaign: %v", err)
	}
	if ok := objAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Fatalf("ok = %v, want true", ok)
	}
}
