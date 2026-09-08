package cli

// P1b CLI tests — `prove` (ord 55).
//
// Ports: tests/test_completion_proofs.py through the CLI: the all-stages
// board (sorted, DONE/open + authoritative/advisory + first three missing
// subjects), the single-stage JSON view whose exit code IS the verdict, and
// the unknown-stage note (a deterministic stage without an advisory proof).

import (
	"encoding/json"
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

func TestProveStageJSONAndExitCode(t *testing.T) {
	// An unresolved tier-3 candidate pair is what makes the dedup proof open
	// (a fresh campaign has no advisory dedup proof at all).
	c, root, _, _ := t15Pair(t)
	code, out, errS := run(t, "--root", root, "prove", c.CampaignID,
		"--stage", "dedup")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (the proof is not done): %q", code, errS)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	got := keyOrder(t, out)
	want := []string{"done", "missing", "note", "stage", "authoritative"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("key order %v, want %v", got, want)
	}
	if doc["stage"] != "dedup" || doc["done"] != false {
		t.Fatalf("doc %v", doc)
	}
}

func TestProveUnknownStageIsDeterministic(t *testing.T) {
	c, root := t15Campaign(t, "prove")
	code, out, errS := run(t, "--root", root, "prove", c.CampaignID,
		"--stage", "no-such-stage")
	if code != 0 {
		t.Fatalf("exit %d, want 0: %q", code, errS)
	}
	if out != "no-such-stage: no completion proof declared "+
		"(deterministic stage without an advisory proof)\n" {
		t.Fatalf("output %q", out)
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
