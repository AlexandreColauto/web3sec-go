package report

// Task 8 (G11) report tests — the patch-regression line beside the
// immunize clause: presence-gated on verification.patch_regression, one
// line per verdict label plus the detail second line.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ppBaselineExec reads the baseline repro exec the finding's minted
// evidence cites (what mk() registered).
func ppBaselineExec(t *testing.T, camp *state.Campaign,
	fid string) string {
	t.Helper()
	f, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range listAt(f, "evidence") {
		if aid := validation.ObjStr(e, "artifact_id"); strings.HasPrefix(aid,
			"EXEC-") {
			return aid
		}
	}
	t.Fatal("no baseline exec cited on the finding")
	return ""
}

// ppWriteRegression lands a verification.patch_regression record through
// the SaveFinding path (the shape verify --post-patch writes).
func ppWriteRegression(t *testing.T, camp *state.Campaign, fid, verdict,
	exec, base, detail string) {
	t.Helper()
	f, err := findings.LoadFinding(camp, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := validation.ObjAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "patch_regression",
		validation.VObj(
			kv("verdict", validation.VStr(verdict)),
			kv("exec", validation.VStr(exec)),
			kv("base_exec", validation.VStr(base)),
			kv("detail", validation.VStr(detail)),
			kv("snapshot", validation.VNull())))
	f.O = validation.SetOrAppend(f.O, "verification", ver)
	if err := findings.SaveFinding(camp, &f); err != nil {
		t.Fatal(err)
	}
}

func TestPatchRegressionStillReproducible(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	fid := validation.ObjStr(fs[2], "finding_id")
	base := ppBaselineExec(t, camp, fid)
	ppWriteRegression(t, camp, fid, "still_reproducible", "EXEC-ppnew0001",
		base, "post-patch EXEC-ppnew0001 exits 0 with stdout matching "+
			"baseline "+base)
	sec := reportFindingSection(t, mustGenerate(t, camp), fid)
	want := "- patch regression: **STILL REPRODUCIBLE** (" + base +
		" → EXEC-ppnew0001)"
	if !strings.Contains(sec, want) {
		t.Fatalf("missing regression line:\n%s", sec)
	}
	if !strings.Contains(sec, "- post-patch EXEC-ppnew0001 exits 0") {
		t.Fatalf("missing detail second line:\n%s", sec)
	}
}

func TestPatchRegressionFixed(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	fid := validation.ObjStr(fs[0], "finding_id")
	base := ppBaselineExec(t, camp, fid)
	ppWriteRegression(t, camp, fid, "fixed", "EXEC-ppnew0002", base,
		"baseline "+base+" exits 0; post-patch EXEC-ppnew0002 exits 1")
	sec := reportFindingSection(t, mustGenerate(t, camp), fid)
	want := "- patch regression: **FIXED** (" + base + " → EXEC-ppnew0002)"
	if !strings.Contains(sec, want) {
		t.Fatalf("missing regression line:\n%s", sec)
	}
}

func TestPatchRegressionIndeterminateNoDetailLine(t *testing.T) {
	camp := clusterCamp(t)
	fs := fourSurfaces(t, camp)
	fid := validation.ObjStr(fs[1], "finding_id")
	base := ppBaselineExec(t, camp, fid)
	ppWriteRegression(t, camp, fid, "indeterminate", "EXEC-ppnew0003",
		base, "")
	sec := reportFindingSection(t, mustGenerate(t, camp), fid)
	want := "- patch regression: **INDETERMINATE** (" + base +
		" → EXEC-ppnew0003)"
	if !strings.Contains(sec, want) {
		t.Fatalf("missing regression line:\n%s", sec)
	}
	// An empty detail renders no second line: no bare "- " line may
	// appear anywhere in the section.
	for _, ln := range strings.Split(sec, "\n") {
		if ln == "- " || ln == "-" {
			t.Fatalf("bare detail line rendered:\n%s", sec)
		}
	}
}

func TestPatchRegressionAbsentRendersNothing(t *testing.T) {
	camp := clusterCamp(t)
	_ = fourSurfaces(t, camp)
	text := mustGenerate(t, camp)
	if strings.Contains(text, "patch regression") {
		t.Fatal("patch-regression line rendered without a record")
	}
}
