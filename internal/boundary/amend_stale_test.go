package boundary

// amend_stale_test.go: G14a amend re-stales the critic — a verdict that
// addressed the pre-amend claim is refused after the amend bumps
// claim_version, through the real ValidateResponse stale-check
// (boundary.go validateCriticVerdict).

import (
	"strings"
	"testing"
	"websec/internal/validation"

	"websec/internal/findings"
)

func TestAmendRestalesCriticVerdict(t *testing.T) {
	c := newCamp(t)
	fid := criticSetup(t, c)
	v := validCriticVerdict(fid)
	// The verdict addresses the current claim: it validates.
	if err := ValidateResponse("critic", "critic_verdict", v, c); err != nil {
		t.Fatalf("pre-amend verdict rejected: %v", err)
	}
	// Amend bumps claim_version 1 -> 2 (status untouched).
	got, err := findings.Amend(c, fid, findings.AmendOpts{
		Title:    "updated claim after the reviewer read the vault code",
		HasTitle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := validation.ObjAt(got, "claim_version"); v.I != 2 {
		t.Fatalf("claim_version = %v, want 2", v)
	}
	// The same verdict payload is now stale-refused.
	err = ValidateResponse("critic", "critic_verdict", v, c)
	if err == nil || !strings.Contains(err.Error(), "stale critic verdict") {
		t.Fatalf("post-amend verdict err = %v, want stale refusal", err)
	}
}
