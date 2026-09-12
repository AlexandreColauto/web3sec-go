package cli

// P1b CLI tests — `waive` (ord 54).
//
// Ports: tests/test_completion_proofs.py's waive semantics through the CLI
// (a waiver is a named actor + a written reason; --subject omitted means the
// whole stage).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWaiveWholeStage(t *testing.T) {
	c, root := t15Campaign(t, "waive")
	code, out, errS := run(t, "--root", root, "waive", c.CampaignID, "dedup",
		"--reason", "dedup proof waived for the CLI test", "--actor", "t15")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "waived dedup/* (actor t15): dedup proof waived for the CLI test\n" {
		t.Fatalf("output %q", out)
	}
}

func TestWaiveNamedSubject(t *testing.T) {
	c, root := t15Campaign(t, "waive")
	code, out, errS := run(t, "--root", root, "waive", c.CampaignID,
		"reproduction", "--subject", "ladder", "--reason",
		"subject waiver for the CLI test", "--actor", "t15")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "waived reproduction/ladder (actor t15): subject waiver for the CLI test\n" {
		t.Fatalf("output %q", out)
	}
}

func TestWaiveShortReasonRefused(t *testing.T) {
	c, root := t15Campaign(t, "waive")
	code, _, errS := run(t, "--root", root, "waive", c.CampaignID, "dedup",
		"--reason", "short", "--actor", "t15")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errS, "written reason") {
		t.Fatalf("stderr %q", errS)
	}
}

func TestWaiveMissingOptionsIsArgparse(t *testing.T) {
	code, _, errS := run(t, "waive", "C-x", "dedup")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["waive"] +
		"webv2 waive: error: the following arguments are required: " +
		"--reason, --actor\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

// TestWaiveTruncatesReasonAt60 pins the console line's cap: the full reason
// lives in the waiver record, the line names the first 60 chars.
func TestWaiveTruncatesReasonAt60(t *testing.T) {
	c, root := t15Campaign(t, "waive")
	reason := strings.Repeat("r", 80)
	code, out, errS := run(t, "--root", root, "waive", c.CampaignID, "dedup",
		"--reason", reason, "--actor", "t15")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(out, ": "+strings.Repeat("r", 60)+"\n") {
		t.Fatalf("output %q", out)
	}
}

// TestWaiveRefusesTypoStage: a stage the waiver system never reads would
// record a row that satisfies no proof and no gate check while `waive`
// reports success — refused at exit 2 with the valid list named. Negative
// controls: both halves of the vocabulary (a pipeline stage and a check
// rail) are accepted.
func TestWaiveRefusesTypoStage(t *testing.T) {
	c, root := t15Campaign(t, "waive-typo")
	code, _, errS := run(t, "--root", root, "waive", c.CampaignID,
		"discovrey", "--reason", "typo'd stage must be refused outright",
		"--actor", "t15")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if !strings.Contains(errS,
		"'discovrey' is not a stage the waiver system reads") ||
		!strings.Contains(errS, "would satisfy nothing") {
		t.Fatalf("stderr %q", errS)
	}
	if !strings.Contains(errS, "discovery") ||
		!strings.Contains(errS, "adversarial-game") ||
		!strings.Contains(errS, "paid-exploitability") ||
		!strings.Contains(errS, "immunization") {
		t.Fatalf("refusal does not name the valid list: %q", errS)
	}
	// negative controls: the typo'd refusal wrote nothing, and the real
	// stages still waive
	if _, err := os.Stat(filepath.Join(c.Dir, "waivers.jsonl")); err == nil {
		t.Fatalf("refused waiver wrote a waivers file")
	}
	code, out, errS := run(t, "--root", root, "waive", c.CampaignID, "learning",
		"--reason", "the proof vocabulary accepts a stage id", "--actor", "t15")
	if code != 0 || !strings.HasPrefix(out, "waived learning/") {
		t.Fatalf("stage rail refused: exit %d out %q err %q", code, out, errS)
	}
	code, out, errS = run(t, "--root", root, "waive", c.CampaignID,
		"adversarial-game", "--subject", "F-000000000000",
		"--reason", "the check rail is part of the vocabulary", "--actor", "t15")
	if code != 0 || !strings.HasPrefix(out, "waived adversarial-game/") {
		t.Fatalf("check rail refused: exit %d out %q err %q", code, out, errS)
	}
}
