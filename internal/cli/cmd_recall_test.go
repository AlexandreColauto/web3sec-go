package cli

// P1b CLI tests — `recall` (ord 46).
//
// Ports: tests/test_cli_recall.py (rows + the recorded memory check, the
// comparative mode's requirement), tests/test_cli.py's ladder step (recall
// records the memory check the CONFIRMED gate reads), and the four CLI
// tests at the end of tests/test_recall_relevance.py (the relevance verdict
// is reported at the moment of the act).

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

func TestRecallPrintsRowsAndRecordsCheck(t *testing.T) {
	c, root := t15Campaign(t, "recall")
	t15GlobalRow(t, "MEM-shared01", "logic-error")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := objStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", fid, "--mode", "negative")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "MEM-shared01") {
		t.Fatalf("output must list the visible row:\n%s", out)
	}
	if !strings.Contains(out, "recorded: mode=negative on "+fid+
		" (1 total memory check(s))") {
		t.Fatalf("output must report the recording:\n%s", out)
	}
	reloaded, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	checks := objAt(objAt(reloaded, "provenance"), "memory_checks")
	if len(checks.A) != 1 {
		t.Fatalf("memory_checks = %v", validation.DumpIndentedASCII(checks))
	}
	if got := strListCLI(objAt(checks.A[0], "memory_ids")); len(got) != 1 ||
		got[0] != "MEM-shared01" {
		t.Fatalf("recorded ids %v", got)
	}
}

func TestRecallComparativeRequiresNote(t *testing.T) {
	c, root := t15Campaign(t, "recall")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	code, _, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", objStr(f, "finding_id"), "--mode", "comparative")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "comparative") || !strings.Contains(errS, "--note") {
		t.Fatalf("stderr %q", errS)
	}
}

func TestRecallMissingFindingIsArgparse(t *testing.T) {
	code, _, errS := run(t, "recall", "C-x")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := argparseUsageBlocks["recall"] +
		"webv2 recall: error: the following arguments are required: --finding\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestRecallUnknownFinding(t *testing.T) {
	c, root := t15Campaign(t, "recall")
	code, _, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", "F-000000000000")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errS, "no finding") {
		t.Fatalf("stderr %q", errS)
	}
}

// ---- tests/test_recall_relevance.py CLI tail ------------------------------

func TestRecallCLIReportsTheRelevanceVerdict(t *testing.T) {
	c, root := t15Campaign(t, "test-program")
	t15GlobalRow(t, "MEM-defi0001", "oracle-manipulation")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	code, out, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", objStr(f, "finding_id"))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "no overlapping row") {
		t.Fatalf("output must report no overlap:\n%s", out)
	}
	if !strings.Contains(out, "corpus.gap") {
		t.Fatalf("output must log the corpus gap:\n%s", out)
	}
}

func TestRecallCLINamesTheDiscountedCoarseClass(t *testing.T) {
	c, root := t15Campaign(t, "test-program")
	t15GlobalRow(t, "MEM-coarse01", "logic-error")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	code, out, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", objStr(f, "finding_id"))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{"no overlapping row", "bug_class=logic-error",
		"second basis"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRecallCLILegacyEntryIsNotRestamped(t *testing.T) {
	c, root := t15Campaign(t, "test-program")
	t15GlobalRow(t, "MEM-old00001", "logic-error")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	fid := objStr(f, "finding_id")
	row, _ := findings.VisibleMemoryRows(c)
	legacy := validation.VObj(
		kvT("memory_ids", validation.VArr(validation.VStr("MEM-old00001"))),
		kvT("mode", validation.VStr("negative")),
		kvT("consulted_at", validation.VStr("2026-09-01T00:00:00+00:00")),
		kvT("row_digest", validation.VStr("sha256:"+
			strings.Repeat("0", 64))),
	)
	found := f
	prov := asDictCLI(objAt(found, "provenance"))
	prov = setObjFieldCLI(prov, "memory_checks", validation.VArr(legacy))
	found = setObjFieldCLI(found, "provenance", prov)
	if err := findings.SaveFinding(c, &found); err != nil {
		t.Fatal(err)
	}
	_ = row
	code, out, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", fid)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "predates the relevance test") {
		t.Fatalf("output must not imply a fresh verdict:\n%s", out)
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	checks := objAt(objAt(stored, "provenance"), "memory_checks")
	if len(checks.A) != 1 {
		t.Fatalf("the legacy entry must dedupe the recording: %v",
			validation.DumpIndentedASCII(checks))
	}
}

func TestRecallRecordsDedupe(t *testing.T) {
	c, root := t15Campaign(t, "test-program")
	t15GlobalRow(t, "MEM-global01", "logic-error")
	f := t15Finding(t, c, "Recall probe finding", "logic-error")
	fid := objStr(f, "finding_id")
	for i := 0; i < 2; i++ {
		code, _, errS := run(t, "--root", root, "recall", c.CampaignID,
			"--finding", fid)
		if code != 0 {
			t.Fatalf("run %d exit %d: %q", i, code, errS)
		}
	}
	stored, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	checks := objAt(objAt(stored, "provenance"), "memory_checks")
	if len(checks.A) != 1 {
		t.Fatalf("the identical check must dedupe: %v", validation.DumpIndentedASCII(checks))
	}
}

func TestRecallRagSubcommandGone(t *testing.T) {
	_, root := t15Campaign(t, "test-program")
	code, _, _ := run(t, "--root", root, "rag", "C-x", "F-1", "--chunk", "X")
	if code == 0 {
		t.Fatal("`rag` must be an unknown subcommand")
	}
}

func TestRecallCLILabelOnlyGapDoesNotClaimCorpusSilence(t *testing.T) {
	c, root := t15Campaign(t, "test-program")
	t15GlobalRow(t, "MEM-rollup01", "logic-error")
	f := t15Finding(t, c, "an inflation hypothesis", "logic-error")
	code, out, errS := run(t, "--root", root, "recall", c.CampaignID,
		"--finding", objStr(f, "finding_id"))
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	for _, want := range []string{"no overlapping row",
		"non-discriminative class label", "bug_class=logic-error"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToLower(out), "silent") {
		t.Fatalf("output must not claim corpus silence:\n%s", out)
	}
}
