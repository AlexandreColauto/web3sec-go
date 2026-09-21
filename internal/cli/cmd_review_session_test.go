package cli

import (
	"strings"
	"testing"

	"websec/internal/state"
)

func TestReviewSessionStartEnd(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	code, out, errS := run(t, "--root", root, "review-session", "start",
		"--actor", "operator", "--artifact", "src/V.sol")
	if code != 0 {
		t.Fatalf("start code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "review session RS-") {
		t.Fatalf("stdout = %q", out)
	}
	code, out, errS = run(t, "--root", root, "review-session", "end", "--loc", "412")
	if code != 0 {
		t.Fatalf("end code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "412 lines") {
		t.Fatalf("stdout = %q, want the LOC line", out)
	}
}

func TestReviewSessionEndWithoutStartIsExit2(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	code, _, errS := run(t, "--root", root, "review-session", "end", "--loc", "10")
	if code != 2 || !strings.Contains(errS, "no open review session") {
		t.Fatalf("code = %d stderr = %q", code, errS)
	}
}

// TestReviewSessionNamesACampaignOnAnAmbiguousRoot: the projection lives in
// campaign_state.review_sessions, so an operator holding several campaigns
// must be able to say which one they are reviewing — otherwise the verb is
// unusable on any root with two campaigns, and the session lands in whichever
// campaign the resolver guessed.
func TestReviewSessionNamesACampaignOnAnAmbiguousRoot(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	beta, err := state.Init(root, "Beta", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Without the positional the root is ambiguous, and the verb says so.
	code, _, errS := run(t, "--root", root, "review-session", "start")
	if code != 2 || !strings.Contains(errS, "name one") {
		t.Fatalf("code = %d stderr = %q, want the ambiguous-root refusal", code, errS)
	}
	// Naming the campaign resolves it.
	code, out, errS := run(t, "--root", root, "review-session", "start",
		beta.CampaignID, "--actor", "operator")
	if code != 0 {
		t.Fatalf("start code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "review session RS-") {
		t.Fatalf("stdout = %q", out)
	}
	// And the session is stored against THAT campaign, not the other one.
	code, out, errS = run(t, "--root", root, "review-session", "end", beta.CampaignID,
		"--loc", "88")
	if code != 0 {
		t.Fatalf("end code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "88 lines") {
		t.Fatalf("stdout = %q, want the LOC line", out)
	}
}
