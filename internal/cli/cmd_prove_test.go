package cli

// P1b CLI tests — `prove` (ord 55).
//
// Ports: tests/test_completion_proofs.py through the CLI: the all-stages
// board (sorted, DONE/open + authoritative/advisory + first three missing
// subjects), the single-stage JSON view whose exit code IS the verdict, and
// the unknown-stage note (a deterministic stage without an advisory proof).

import (
	"strings"
	"testing"
)

func TestProveAllStagesBoard(t *testing.T) {
	c, root := t15Campaign(t, "prove")
	code, out, errS := run(t, "--root", root, "prove", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("board too short:\n%s", out)
	}
	// Sorted by stage id, padded to 26 columns, then the mark and basis.
	for _, ln := range lines {
		if len(ln) < 27 || ln[26] != ' ' {
			t.Fatalf("row %q is not 26-column padded", ln)
		}
		if !strings.Contains(ln, "DONE ") && !strings.Contains(ln, "open ") {
			t.Fatalf("row %q has no mark", ln)
		}
		if !strings.Contains(ln, "[authoritative]") &&
			!strings.Contains(ln, "[advisory]") {
			t.Fatalf("row %q has no basis", ln)
		}
	}
	ids := make([]string, 0, len(lines))
	for _, ln := range lines {
		ids = append(ids, strings.TrimRight(ln[:26], " "))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("stages not sorted: %v", ids)
		}
	}
	// A fresh campaign is open everywhere and names what is missing.
	if !strings.Contains(out, "open  [advisory] — ") {
		t.Fatalf("board must name the missing subjects:\n%s", out)
	}
}

func TestProveStageHumanSummaryAndExitCode(t *testing.T) {
	// An unresolved tier-3 candidate pair is what makes the dedup proof open
	// (a fresh campaign has no advisory dedup proof at all).
	// feedback-triage A6: --stage now prints the same human-readable line
	// as the board view instead of the raw proof JSON (intentional
	// divergence); the exit code is still the done/not-done verdict.
	c, root, _, _ := t15Pair(t)
	code, out, errS := run(t, "--root", root, "prove", c.CampaignID,
		"--stage", "dedup")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (the proof is not done): %q", code, errS)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one summary line:\n%s", out)
	}
	ln := lines[0]
	if len(ln) < 27 || ln[26] != ' ' {
		t.Fatalf("line %q is not 26-column padded", ln)
	}
	if got := strings.TrimRight(ln[:26], " "); got != "dedup" {
		t.Fatalf("stage column %q, want dedup", got)
	}
	// mark is "open " and the Sprintf adds its own separator space, so the
	// rendered line carries "open  [advisory]" (two spaces).
	if !strings.Contains(ln, "open  [advisory]") {
		t.Fatalf("line %q lacks the open mark + basis", ln)
	}
	if !strings.Contains(ln, "[advisory] — ") {
		t.Fatalf("line %q lacks basis and missing subjects", ln)
	}
	if !strings.Contains(ln, "no normalization verdict") {
		t.Fatalf("line %q must name the missing subject", ln)
	}
}

// TestProveUnknownStageIsDeterministic — r5 issue 5 REVERSED the old
// determinism: a stage-name typo now REFUSES (exit 2) instead of echoing
// the proofless-stage sentence it was ported to imitate. The membership
// list is the fix; a real proofless stage keeps the original line.
func TestProveUnknownStageIsDeterministic(t *testing.T) {
	c, root := t15Campaign(t, "prove")
	code, _, errS := run(t, "--root", root, "prove", c.CampaignID,
		"--stage", "no-such-stage")
	if code != 2 || !strings.Contains(errS, "not a campaign stage") {
		t.Fatalf("typo must refuse: exit %d %q", code, errS)
	}
	code, out, errS := run(t, "--root", root, "prove", c.CampaignID,
		"--stage", "scope")
	if code != 0 || out != "scope: no completion proof declared "+
		"(deterministic stage without an advisory proof)\n" {
		t.Fatalf("real proofless stage changed: exit %d %q %q", code, out,
			errS)
	}
}

func TestProveUnknownCampaign(t *testing.T) {
	root := t.TempDir()
	code, _, errS := run(t, "--root", root, "prove", "C-0000000000")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("stderr %q", errS)
	}
}

func TestProveMissingCampaignIsArgparse(t *testing.T) {
	code, _, errS := run(t, "prove")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["prove"] +
		"webv2 prove: error: the following arguments are required: campaign\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestProveUnknownStageRefused pins r5 issue 5: a typo must not wear the
// face of a legitimate "stage has no proof".
func TestProveUnknownStageRefused(t *testing.T) {
	root := t.TempDir()
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "prove", cid,
		"--stage", "bogus-stage")
	if code != 2 || !strings.Contains(errS, "not a campaign stage") ||
		!strings.Contains(errS, "planning") {
		t.Fatalf("typo stage must refuse + list: exit %d out %q err %q",
			code, out, errS)
	}
	// A real proofless stage keeps its old answer:
	code, out, errS = run(t, "--root", root, "prove", cid,
		"--stage", "snapshot")
	if code != 0 || !strings.Contains(out, "no completion proof") {
		t.Fatalf("real stage behavior changed: exit %d %q %q", code, out,
			errS)
	}
}
