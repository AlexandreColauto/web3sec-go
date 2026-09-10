// plan_rebuild_test.go: tests/test_plan_rebuild.py's pre-validation pin,
// ported at the orchestrator boundary. The CLI itself (`webv2 plan <C>
// --rebuild`, exit codes and stderr) is T14's job; this covers the ordering
// contract the CLI relies on.
package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// TestBadRebuildCreatesNoArchive is
// tests/test_plan_rebuild.py::test_bad_file_rebuild_creates_no_archive: the
// incoming plan is validated BEFORE the outgoing one is archived, so a
// `--rebuild` that cannot produce a writable plan fails loudly without
// retiring the live contract and without leaving a misleading archive of a
// plan that is still in force.
func TestBadRebuildCreatesNoArchive(t *testing.T) {
	portWireSeams(t)
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	o := New(c)
	portInstallIndex(t)
	if _, err := o.LoadProtocolModel(portJSON(t, portModel)); err != nil {
		t.Fatalf("load protocol model: %v", err)
	}
	if _, err := o.Plan(validation.VNull(), validation.VNull(), false); err != nil {
		t.Fatalf("first plan: %v", err)
	}
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	beforeBytes, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(planPath)
	if err != nil {
		t.Fatal(err)
	}

	// a plan that cannot be written: a non-canonical bug_class
	bad, err := validation.ReadJson(planPath)
	if err != nil {
		t.Fatal(err)
	}
	bad = setPriorityField(bad, "bug_class", validation.VStr("not-a-canonical-class"))
	if _, err := o.Plan(bad, validation.VNull(), true); err == nil {
		t.Fatal("bad rebuild must fail loudly")
	} else if !strings.Contains(err.Error(), "bug_class") {
		t.Fatalf("error does not name the offending field: %v", err)
	}

	afterBytes, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBytes) != string(beforeBytes) {
		t.Fatalf("live plan changed:\n%s", afterBytes)
	}
	afterInfo, err := os.Stat(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
		t.Errorf("plan mtime changed: %s != %s", afterInfo.ModTime(),
			beforeInfo.ModTime())
	}
	if _, err := os.Stat(filepath.Join(c.ArtifactsDir, "superseded")); !os.IsNotExist(err) {
		t.Errorf("superseded/ exists (err=%v)", err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strAt(e, "type") == "plan.superseded" {
			t.Errorf("plan.superseded event recorded: %s",
				validation.CanonCompact(e))
		}
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range listAt(st, "artifacts") {
		if strAt(a, "kind") == "plan.superseded" {
			t.Errorf("plan.superseded artifact registered: %s",
				validation.CanonCompact(a))
		}
	}
}

// setPriorityField is the recorded mutation: plan["priorities"][0][key] = v.
func setPriorityField(plan validation.Value, key string,
	v validation.Value) validation.Value {
	priorities := listAt(plan, "priorities")
	if len(priorities) == 0 {
		return plan
	}
	first := validation.SetOrAppend(priorities[0].O, key, v)
	priorities[0] = validation.VObj(first...)
	return validation.VObj(validation.SetOrAppend(plan.O, "priorities",
		validation.VArr(priorities...))...)
}
