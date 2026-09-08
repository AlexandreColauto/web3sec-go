package cli

// P1b CLI tests — `resolve-candidate` (ord 64).
//
// Ports: tests/test_dedup.py's resolve_candidate contract through the CLI:
// the verdict is recorded on BOTH sides, 'same' merges the younger side, an
// unflagged pair is a KeyError-shaped exit-2 line, and a note shorter than 5
// chars is refused. The note path reproduces the reference's own schema
// failure (dedup_meta.candidate_notes is declared as a string map) — a
// byte-exact port of the bug, pinned here so a future "fix" cannot silently
// diverge.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// t15Pair ingests two findings and flags the second as a tier-3 candidate.
func t15Pair(t *testing.T) (*state.Campaign, string, validation.Value,
	validation.Value) {
	t.Helper()
	c, root := t15Campaign(t, "resolve")
	f1 := t15Finding(t, c, "the first hypothesis", "logic-error")
	f2 := t15Finding(t, c, "the second hypothesis", "logic-error")
	if _, err := findings.FlagPossibleDuplicate(c, objStr(f2, "finding_id"),
		objStr(f1, "finding_id")); err != nil {
		t.Fatalf("flag: %v", err)
	}
	return c, root, f1, f2
}

func TestResolveCandidateDistinct(t *testing.T) {
	c, root, f1, f2 := t15Pair(t)
	code, out, errS := run(t, "--root", root, "resolve-candidate",
		c.CampaignID, objStr(f2, "finding_id"), objStr(f1, "finding_id"),
		"--verdict", "distinct", "--actor", "operator")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "candidate pair " + objStr(f2, "finding_id") + " vs " +
		objStr(f1, "finding_id") + ": distinct (recorded on both sides)\n"
	if out != want {
		t.Fatalf("output %q, want %q", out, want)
	}
	for _, f := range []validation.Value{f1, f2} {
		reloaded, err := findings.LoadFinding(c, objStr(f, "finding_id"))
		if err != nil {
			t.Fatal(err)
		}
		verdicts := objAt(objAt(reloaded, "dedup"), "candidate_verdicts")
		other := objStr(f1, "finding_id")
		if objStr(f, "finding_id") == other {
			other = objStr(f2, "finding_id")
		}
		if got := scalarStr(objAt(verdicts, other)); got != "distinct" {
			t.Fatalf("verdict for %s = %q, want distinct", other, got)
		}
	}
}

func TestResolveCandidateSameMergesYoungerSide(t *testing.T) {
	c, root, f1, f2 := t15Pair(t)
	code, _, errS := run(t, "--root", root, "resolve-candidate", c.CampaignID,
		objStr(f2, "finding_id"), objStr(f1, "finding_id"), "--verdict", "same")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	statuses := map[string]string{}
	for _, f := range []validation.Value{f1, f2} {
		reloaded, err := findings.LoadFinding(c, objStr(f, "finding_id"))
		if err != nil {
			t.Fatal(err)
		}
		statuses[objStr(reloaded, "finding_id")] = objStr(reloaded, "status")
	}
	if statuses[objStr(f1, "finding_id")] == "DUPLICATE" &&
		statuses[objStr(f2, "finding_id")] == "DUPLICATE" {
		t.Fatalf("only the younger side merges: %v", statuses)
	}
	if statuses[objStr(f1, "finding_id")] != "DUPLICATE" &&
		statuses[objStr(f2, "finding_id")] != "DUPLICATE" {
		t.Fatalf("no side was merged: %v", statuses)
	}
}

func TestResolveCandidateUnflaggedPairIsKeyErrorShaped(t *testing.T) {
	c, root := t15Campaign(t, "resolve")
	f1 := t15Finding(t, c, "the first hypothesis", "logic-error")
	f2 := t15Finding(t, c, "the second hypothesis", "logic-error")
	code, _, errS := run(t, "--root", root, "resolve-candidate", c.CampaignID,
		objStr(f2, "finding_id"), objStr(f1, "finding_id"), "--verdict", "same")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := "resolve-candidate failed: \"" + objStr(f2, "finding_id") +
		" has no candidate flag for '" + objStr(f1, "finding_id") +
		"'; run the dedup sweep first\"\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestResolveCandidateNoteTooShort(t *testing.T) {
	c, root, f1, f2 := t15Pair(t)
	code, _, errS := run(t, "--root", root, "resolve-candidate", c.CampaignID,
		objStr(f2, "finding_id"), objStr(f1, "finding_id"), "--verdict",
		"distinct", "--note", "hi")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if errS != "resolve-candidate failed: a candidate verdict note, when "+
		"given, must be substantive\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestResolveCandidateUnknownFinding(t *testing.T) {
	c, root := t15Campaign(t, "resolve")
	code, _, errS := run(t, "--root", root, "resolve-candidate", c.CampaignID,
		"F-000000000000", "F-000000000001", "--verdict", "same")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (FileNotFoundError is not caught)", code)
	}
	if !strings.Contains(errS, "no finding 'F-000000000000'") {
		t.Fatalf("stderr %q", errS)
	}
}

func TestResolveCandidateInvalidChoiceIsArgparse(t *testing.T) {
	code, _, errS := run(t, "resolve-candidate", "C-x", "F-x", "F-y",
		"--verdict", "bogus")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["resolve-candidate"] +
		"webv2 resolve-candidate: error: argument --verdict: invalid choice: " +
		"'bogus' (choose from 'same', 'distinct')\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestResolveCandidateMissingVerdictIsArgparse(t *testing.T) {
	code, _, errS := run(t, "resolve-candidate", "C-x", "F-x", "F-y")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["resolve-candidate"] +
		"webv2 resolve-candidate: error: the following arguments are " +
		"required: --verdict\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}
