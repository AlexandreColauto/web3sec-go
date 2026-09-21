package cli

// cmd_impact tests — `impact` (ord 47): argparse vectors and the captured
// Python handler vectors (figure recording, the named unpriceable decision,
// the artifact/E7 mint, and every refusal's exact stderr).

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/validation"
)

var t23ImpactECORe = regexp.MustCompile(`^ECO-[0-9a-f]+$`)

func TestImpactArgparse(t *testing.T) {
	t23WantHelp(t, []string{"impact", "--help"}, t23ImpactHelp)
	t23WantArgparse(t, []string{"impact"}, t23ImpactUsage,
		"webv2 impact: error: the following arguments are required: "+
			"campaign, finding\n")
	t23WantArgparse(t, []string{"impact", "C"}, t23ImpactUsage,
		"webv2 impact: error: the following arguments are required: finding\n")
	t23WantArgparse(t, []string{"impact", "C", "F", "--extractable", "abc"},
		t23ImpactUsage,
		"webv2 impact: error: argument --extractable: invalid float value: "+
			"'abc'\n")
	t23WantArgparse(t, []string{"impact", "C", "F", "--max-loss", "x"},
		t23ImpactUsage,
		"webv2 impact: error: argument --max-loss: invalid float value: 'x'\n")
	t23WantArgparse(t, []string{"impact", "C", "F", "--required-capital", "y"},
		t23ImpactUsage,
		"webv2 impact: error: argument --required-capital: invalid float "+
			"value: 'y'\n")
	t23WantArgparse(t, []string{"impact", "C", "F", "--bogus"}, t14TopUsage,
		"webv2: error: unrecognized arguments: --bogus\n")
	t23WantArgparse(t, []string{"impact", "C", "F", "extra"}, t14TopUsage,
		"webv2: error: unrecognized arguments: extra\n")
}

// TestImpactOptionValueSlot pins argparse's rule that an option-looking token
// is not consumed as a value (captured Python vector).
func TestImpactOptionValueSlot(t *testing.T) {
	t23WantArgparse(t, []string{"impact", "C", "F", "--reason", "-foo"},
		t23ImpactUsage,
		"webv2 impact: error: argument --reason: expected one argument\n")
}

// TestImpactNegativeFigureAccepted: -5 IS consumed as a value (argparse's
// negative-number rule) and then refused by the schema — the captured Python
// message, exit 1.
func TestImpactNegativeFigureAccepted(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-negative")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--extractable", "-5")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	want := "error: finding validation failed at economic_impact/" +
		"extractable_usd: -5.0 is less than the minimum of 0 " +
		"(+0 more errors)\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestImpactRequiresFigure(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-figure")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid)
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	want := "impact requires --extractable USD and/or --max-loss USD, or --reversibility MODE\n"
	if errS != want {
		t.Fatalf("stderr %q want %q", errS, want)
	}
}

// TestImpactReversibilityOnly pins the E5 classification-only call: no USD
// figure, just the victim-perspective recoverability, and the recalibrated
// band in the output line.
func TestImpactReversibilityOnly(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-reversibility")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--reversibility", "irreversible")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, fid+": reversibility recorded — irreversible (risk band ") {
		t.Fatalf("out %q", out)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(f, "risk"), "reversibility"); got != "irreversible" {
		t.Errorf("stored reversibility = %q", got)
	}
	score := validation.ObjAt(validation.ObjAt(validation.ObjAt(f, "risk"), "validated"), "score")
	if score.Kind != validation.Flt || score.F < 6.5 {
		t.Errorf("validated score = %v; want >= 6.5 after +3.0", score)
	}
}

// TestImpactReversibilityInvalidMode pins the closed-set error (exit 1,
// finding untouched).
func TestImpactReversibilityInvalidMode(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-reversibility-bad")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--reversibility", "unrecoverable-ish")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	if !strings.Contains(errS, "reversibility must be one of") {
		t.Fatalf("stderr %q", errS)
	}
}

// TestImpactRecordsExtractable is the captured Python vector: the stored
// figures (Python float rendering) and the derived risk band.
func TestImpactRecordsExtractable(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-record")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--extractable", "1000")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := fid + ": impact recorded — extractable $1000.0, max loss $None " +
		"(risk band medium)\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

func TestImpactUnpriceableRequiresFlags(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-unprice")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--unpriceable", "--ceiling", "no basis")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	if errS != "impact --unpriceable requires --reason, --actor\n" {
		t.Fatalf("stderr %q", errS)
	}
}

func TestImpactUnpriceableConflict(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-conflict")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--unpriceable", "--ceiling", "no basis", "--reason", "a written "+
			"reason here", "--actor", "op", "--extractable", "5")
	if code != 2 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	want := "impact --unpriceable cannot be combined with --extractable — " +
		"'no figure is defensible' and a figure are mutually exclusive\n"
	if errS != want {
		t.Fatalf("stderr %q want %q", errS, want)
	}
}

func TestImpactUnpriceableRecords(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-unprice-ok")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--unpriceable", "--ceiling", "no basis", "--reason",
		"a written reason here", "--actor", "op")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := fid + ": impact recorded — UNPRICEABLE (ceiling: no basis) — " +
		"named decision logged (finding.unpriceable, actor op)\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
}

func TestImpactMissingFinding(t *testing.T) {
	c, root, _ := t23Campaign(t, "impact-nofind")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID,
		"F-missing0001", "--extractable", "5")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q err %q", code, out, errS)
	}
	want := "error: no finding 'F-missing0001' in " + c.CampaignID + "\n"
	if errS != want {
		t.Fatalf("stderr %q want %q", errS, want)
	}
}

// TestImpactArtifactMissing pins the record-first ordering: the impact line is
// already on stdout when the artifact check fails (exit 2).
func TestImpactArtifactMissing(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-noartifact")
	missing := filepath.Join(t.TempDir(), "nope.json")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--extractable", "1000", "--artifact", missing)
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := fid + ": impact recorded — extractable $1000.0, max loss $None " +
		"(risk band medium)\n"
	if out != want {
		t.Fatalf("stdout\n%q\nwant\n%q", out, want)
	}
	if errS != "impact artifact not found: "+missing+"\n" {
		t.Fatalf("stderr %q", errS)
	}
}

// TestImpactArtifactMints registers a real artifact and mints E7 (the
// captured Python vector's second line).
func TestImpactArtifactMints(t *testing.T) {
	c, root, fid := t23Campaign(t, "impact-artifact")
	if err := os.MkdirAll(c.ArtifactsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dump := filepath.Join(c.ArtifactsDir, "impact-dump.json")
	if err := os.WriteFile(dump, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--extractable", "1000", "--artifact", dump)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout %q", out)
	}
	if lines[0] != fid+": impact recorded — extractable $1000.0, max loss "+
		"$None (risk band medium)" {
		t.Fatalf("line 0 %q", lines[0])
	}
	rest := strings.TrimPrefix(lines[1], fid+": minted E7 evidence vs ")
	if rest == lines[1] || !t23ImpactECORe.MatchString(rest) {
		t.Fatalf("line 1 %q", lines[1])
	}
}

func TestImpactReplayableComputesAndRefusesOneRound(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	f := t15Finding(t, c, "Repeated drain", "economic-invariant")
	fid := validation.ObjStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--replayable", "--extractable-per-round", "500", "--max-loss", "1000000",
		"--gas-cost", "0.05", "--frequency", "1000",
		"--replay-assumption", "no pause triggered",
		"--replay-blocker", "PAUSER_ROLE exists, unexercised")
	if code != 0 {
		t.Fatalf("code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "demonstrated") || !strings.Contains(out, "computed") {
		t.Fatalf("stdout = %q, want both labeled quantities", out)
	}
	code, _, errS = run(t, "--root", root, "impact", c.CampaignID, fid,
		"--replayable", "--extractable-per-round", "500", "--max-loss", "1000",
		"--gas-cost", "0.05", "--rounds-run", "1")
	if code != 2 || !strings.Contains(errS, "two rounds") {
		t.Fatalf("code = %d stderr = %q, want the two-round refusal", code, errS)
	}
	// 1 round extracts 500 from a 500 ceiling, at 5000 of gas: unprofitable.
	code, _, errS = run(t, "--root", root, "impact", c.CampaignID, fid,
		"--replayable", "--extractable-per-round", "500", "--max-loss", "500",
		"--gas-cost", "5000")
	if code != 2 || !strings.Contains(errS, "unprofitable") {
		t.Fatalf("code = %d stderr = %q, want the profitability refusal", code, errS)
	}
}
