// docscan_test.go: port of tests/test_invariants_doc.py — documented
// invariants, intent claims, anchors and reconciliation.
package invariants

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/validation"
)

// protoWithReadme is _proto_with_readme: a tiny protocol tree to pin.
func protoWithReadme(t *testing.T, text string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "protocol")
	if err := os.MkdirAll(filepath.Join(src, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "README.md"), []byte(text),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "src", "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return src
}

const readmeTwoInvs = "INV-1 balances move atomically\n" +
	"INV-002 fees accrue to the treasury\n"

// invModel is the doc test's _model helper.
func invModel(ids ...string) validation.Value {
	invs := make([]validation.Value, len(ids))
	for i, id := range ids {
		invs[i] = validation.VObj(
			kv("id", validation.VStr(id)),
			kv("statement", validation.VStr("statement of "+id)),
			kv("kind", validation.VStr("security")),
			kv("severity_if_broken", validation.VStr("high")),
			kv("applies_to", validation.VArr()),
		)
	}
	return validation.VObj(kv("invariants", validation.VArr(invs...)))
}

func docKeys(v validation.Value) []string {
	out := make([]string, 0, len(v.O))
	for _, e := range v.O {
		out = append(out, e.K)
	}
	sort.Strings(out)
	return out
}

func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		out = append(out, e.S)
	}
	return out
}

// wireCurated wires the playbooks.curated_invariant_ids seam for one test.
func wireCurated(t *testing.T, ids ...string) {
	t.Helper()
	SetCuratedInvariantIDs(func() []string { return ids })
	t.Cleanup(func() {
		SetCuratedInvariantIDs(func() []string { return nil })
	})
}

func TestDocumentedInvariantsFromSnapshot(t *testing.T) {
	c := docCamp(t)
	if _, err := snapshot.PinSourceSnapshot(c, protoWithReadme(t, readmeTwoInvs),
		nil, nil); err != nil {
		t.Fatal(err)
	}
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := docKeys(doc)
	if len(keys) != 2 || keys[0] != "INV-1" || keys[1] != "INV-2" {
		t.Fatalf("documented ids = %v, want [INV-1 INV-2]", keys)
	}
	e := validation.ObjAt(doc, "INV-1")
	if f := validation.ObjStr(e, "file"); !strings.HasPrefix(f, "README") {
		t.Errorf("file = %q, want a README path", f)
	}
	if !strings.Contains(validation.ObjStr(e, "context"), "balances") {
		t.Errorf("context = %q, want the balance line", validation.ObjStr(e, "context"))
	}
}

func TestNoSnapshotMeansEmpty(t *testing.T) {
	c := docCamp(t)
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.O) != 0 {
		t.Fatalf("documented ids = %v, want none", docKeys(doc))
	}
	claims, err := IntentClaims(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.O) != 0 {
		t.Fatalf("intent claims = %v, want none", docKeys(claims))
	}
}

func TestReconcileNoDivergence(t *testing.T) {
	c := docCamp(t)
	if _, err := snapshot.PinSourceSnapshot(c, protoWithReadme(t, readmeTwoInvs),
		nil, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := Reconcile(c, invModel("INV-1", "INV-2"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strList(validation.ObjAt(rep, "missing_from_model")); len(got) != 0 {
		t.Errorf("missing_from_model = %v, want empty", got)
	}
	if got := strList(validation.ObjAt(rep, "extra_in_model")); len(got) != 0 {
		t.Errorf("extra_in_model = %v, want empty", got)
	}
	if got := strList(validation.ObjAt(rep, "documented")); len(got) != 2 {
		t.Errorf("documented = %v, want two ids", got)
	}
}

func TestReconcileReportsDocumentedButMissing(t *testing.T) {
	c := docCamp(t)
	if _, err := snapshot.PinSourceSnapshot(c, protoWithReadme(t, readmeTwoInvs),
		nil, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := Reconcile(c, invModel("INV-1")) // forgot INV-2
	if err != nil {
		t.Fatal(err)
	}
	if got := strList(validation.ObjAt(rep, "missing_from_model")); len(got) != 1 ||
		got[0] != "INV-2" {
		t.Errorf("missing_from_model = %v, want [INV-2]", got)
	}
	if got := strList(validation.ObjAt(rep, "extra_in_model")); len(got) != 0 {
		t.Errorf("extra_in_model = %v, want empty", got)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	var hits []validation.Value
	for _, ev := range events {
		if validation.ObjStr(ev, "type") == "invariants.reconciled" {
			hits = append(hits, ev)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("invariants.reconciled events = %d, want 1", len(hits))
	}
	miss := validation.ObjAt(validation.ObjAt(hits[0], "data"), "missing_from_model")
	if got := strList(miss); len(got) != 1 || got[0] != "INV-2" {
		t.Errorf("logged missing_from_model = %v, want [INV-2]", got)
	}
}

func TestReconcileNotesUndocumentedExtras(t *testing.T) {
	c := docCamp(t)
	if _, err := snapshot.PinSourceSnapshot(c, protoWithReadme(t, readmeTwoInvs),
		nil, nil); err != nil {
		t.Fatal(err)
	}
	rep, err := Reconcile(c, invModel("INV-1", "INV-2", "INV-9"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strList(validation.ObjAt(rep, "missing_from_model")); len(got) != 0 {
		t.Errorf("missing_from_model = %v, want empty", got)
	}
	if got := strList(validation.ObjAt(rep, "extra_in_model")); len(got) != 1 ||
		got[0] != "INV-9" {
		t.Errorf("extra_in_model = %v, want [INV-9]", got)
	}
	if got := validation.ObjStr(rep, "note"); got != "model covers every documented "+
		"invariant id" {
		t.Errorf("note = %q", got)
	}
}

func TestSeedFromModelThenReconcile(t *testing.T) {
	c := docCamp(t)
	if _, err := snapshot.PinSourceSnapshot(c, protoWithReadme(t, readmeTwoInvs),
		nil, nil); err != nil {
		t.Fatal(err)
	}
	model := invModel("INV-1", "INV-99")
	if _, err := SeedFromModel(c, model); err != nil {
		t.Fatal(err)
	}
	rep, err := Reconcile(c, model)
	if err != nil {
		t.Fatal(err)
	}
	if got := strList(validation.ObjAt(rep, "missing_from_model")); len(got) != 1 ||
		got[0] != "INV-2" {
		t.Errorf("missing_from_model = %v, want [INV-2]", got)
	}
}

func TestPlaybookInvariantSeedsAsDocumentedWithProvenance(t *testing.T) {
	c := docCamp(t)
	wireCurated(t, "INV-RE-CEI-ORDERING")
	links, err := SeedFromModel(c, invModel("INV-RE-CEI-ORDERING"))
	if err != nil {
		t.Fatal(err)
	}
	e := validation.ObjAt(validation.ObjAt(links, "invariants"), "INV-RE-CEI-ORDERING")
	if got := validation.ObjStr(e, "source"); got != "documented" {
		t.Errorf("source = %q, want documented", got)
	}
	if got := validation.ObjStr(e, "source_detail"); got != "playbook" {
		t.Errorf("source_detail = %q, want playbook", got)
	}
}

func TestModelInventedInvariantStaysGuarded(t *testing.T) {
	c := docCamp(t)
	links, err := SeedFromModel(c, invModel("INV-ZZZ-CUSTOM-1"))
	if err != nil {
		t.Fatal(err)
	}
	e := validation.ObjAt(validation.ObjAt(links, "invariants"), "INV-ZZZ-CUSTOM-1")
	if got := validation.ObjStr(e, "source"); got != "model" {
		t.Errorf("source = %q, want model", got)
	}
	if validation.HasKey(e, "source_detail") {
		t.Errorf("source_detail present, want absent")
	}
	if got := validation.ObjStr(e, "status"); got != "UNVERIFIED" {
		t.Errorf("status = %q, want UNVERIFIED", got)
	}
}

func TestTargetDocStillWinsAndHasNoPlaybookProvenance(t *testing.T) {
	c := docCamp(t)
	wireCurated(t, "INV-1")
	if _, err := snapshot.PinSourceSnapshot(c, protoWithReadme(t, readmeTwoInvs),
		nil, nil); err != nil {
		t.Fatal(err)
	}
	links, err := SeedFromModel(c, invModel("INV-1"))
	if err != nil {
		t.Fatal(err)
	}
	e := validation.ObjAt(validation.ObjAt(links, "invariants"), "INV-1")
	if got := validation.ObjStr(e, "source"); got != "documented" {
		t.Errorf("source = %q, want documented", got)
	}
	if validation.HasKey(e, "source_detail") {
		t.Errorf("source_detail = %q, want absent (target-docs provenance)",
			validation.ObjStr(e, "source_detail"))
	}
}

// ---- byte-exact doc scans ------------------------------------------------

func TestDocScanMatchesPythonTwin(t *testing.T) {
	c := docCamp(t)
	snapDir := filepath.Join(c.Dir, "snapshots", "SNAPX")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	materializeTree(t, snapDir)
	doc, err := DocumentedInvariants(c, strPtr("SNAPX"))
	if err != nil {
		t.Fatal(err)
	}
	wantGolden(t, "docscan_expected.json", doc)
	if len(doc.O) < 40 {
		t.Fatalf("doc scan found %d ids, want >= 40", len(doc.O))
	}
	// the unicode-boundary and pathlib-suffix cases the twin pins
	for _, absent := range []string{"INV-4", "INV-5", "INV-6", "INV-7",
		"INV-42", "INV-43", "INV-44", "INV-45"} {
		if validation.HasKey(doc, absent) {
			t.Errorf("%s should not be documented (boundary/suffix rule)", absent)
		}
	}
}

func TestIntentClaimsMatchPythonTwin(t *testing.T) {
	c := docCamp(t)
	snapDir := filepath.Join(c.Dir, "snapshots", "SNAPX")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	materializeTree(t, snapDir)
	claims, err := IntentClaims(c, strPtr("SNAPX"))
	if err != nil {
		t.Fatal(err)
	}
	wantGolden(t, "intent_expected.json", claims)
	for _, absent := range []string{"INV-91", "INV-92", "INV-94", "INV-95",
		"INV-96"} {
		if validation.HasKey(claims, absent) {
			t.Errorf("%s should not carry intent language", absent)
		}
	}
}

func TestDocumentedRefMatchesPythonTwin(t *testing.T) {
	c := docCamp(t)
	snapDir := filepath.Join(c.Dir, "snapshots", "SNAPX")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	materializeTree(t, snapDir)
	got := validation.VObj()
	for _, id := range []string{"INV-1", "INV-001", "INV-999", "nope"} {
		ref, err := DocumentedRef(c, id, strPtr("SNAPX"))
		if err != nil {
			t.Fatal(err)
		}
		v := validation.VNull()
		if ref != nil {
			v = validation.VStr(*ref)
		}
		got.O = append(got.O, kv(id, v))
	}
	wantGolden(t, "docref_expected.json", got)
}

func TestMissingSnapshotDocsAreEmpty(t *testing.T) {
	c := docCamp(t)
	doc, err := DocumentedInvariants(c, strPtr("NOPE"))
	if err != nil {
		t.Fatal(err)
	}
	wantGolden(t, "docscan_missing_snapshot.json", doc)
	claims, err := IntentClaims(c, strPtr("NOPE"))
	if err != nil {
		t.Fatal(err)
	}
	wantGolden(t, "intent_missing_snapshot.json", claims)
	ref, err := DocumentedRef(c, "INV-1", strPtr("NOPE"))
	if err != nil {
		t.Fatal(err)
	}
	if ref != nil {
		t.Errorf("ref = %q, want nil for a missing snapshot", *ref)
	}
}

func TestReconcileVectorsMatchPythonTwin(t *testing.T) {
	cases := goldenValue(t, "reconcile_vectors.json")
	if len(cases.A) < 4 {
		t.Fatalf("reconcile vectors = %d, want >= 4", len(cases.A))
	}
	for i, tc := range cases.A {
		c := docCamp(t)
		if _, err := snapshot.PinSourceSnapshot(c,
			protoWithReadme(t, readmeTwoInvs), nil, nil); err != nil {
			t.Fatal(err)
		}
		ids := strList(validation.ObjAt(tc, "ids"))
		rep, err := Reconcile(c, invModel(ids...))
		if err != nil {
			t.Fatal(err)
		}
		want := validation.ObjAt(tc, "rep")
		if validation.DumpIndented(rep) != validation.DumpIndented(want) {
			t.Errorf("reconcile[%d] ids=%v\n got: %s\nwant: %s", i, ids,
				validation.DumpIndented(rep), validation.DumpIndented(want))
		}
	}
}
