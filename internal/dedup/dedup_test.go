package dedup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- fixtures ---------------------------------------------------------------

// dedupCamp is tests/test_dedup_determinism.py's `camp` fixture:
// Campaign.init(tmp_path, "Acme") with nothing pinned.
func dedupCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// pinnedCamp is tests/test_findings.py's `camp` fixture: a campaign with one
// pinned source snapshot (the tier-1/3 tests there never depend on it, but
// snapshot_ids.source is then a real id rather than "unpinned").
func pinnedCamp(t *testing.T) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "V.sol"),
		[]byte("contract V {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// hypo is tests/test_dedup_determinism.py's hypo(): class oracle-manipulation,
// src/Oracle.sol / getPrice. ingest_hypothesis defaults are trajectory="code",
// stage=None, model=None (Go spells None as "").
func hypo(t *testing.T, c *state.Campaign, title string) validation.Value {
	t.Helper()
	return hypoAt(t, c, title, "oracle-manipulation", "src/Oracle.sol", "getPrice")
}

func hypoAt(t *testing.T, c *state.Campaign, title, class, path,
	function string) validation.Value {
	t.Helper()
	payload := validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr("the oracle round method is manipulable")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr(path)),
			kv("function", validation.VStr(function)),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// hypoVault is tests/test_findings.py's hypo(**over): class precision-rounding,
// src/Vault.sol / withdraw.
func hypoVault(t *testing.T, c *state.Campaign, title, class string) validation.Value {
	t.Helper()
	payload := validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr(
				"share calculation rounds in the attacker's favor")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("function", validation.VStr("withdraw")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ---- seam doubles -----------------------------------------------------------

// wireSeams installs faithful doubles for the three findings.py helpers
// internal/findings does not export yet (see the seam block in dedup.go).
// The doubles reproduce exactly the observable contract the sweep depends on:
// mark_duplicate flips the finding to DUPLICATE and records dedup.duplicate_of;
// flag_possible_duplicate appends the candidate id and logs
// finding.possible_duplicate; fold_into_lineage stamps dedup.lineage_id. They
// deliberately do NOT emulate findings.transition's history bookkeeping —
// that lands with internal/findings and is not this package's contract.
func wireSeams(t *testing.T) {
	t.Helper()
	SetMarkDuplicate(func(c *state.Campaign, findingID, ofFindingID string) (validation.Value, error) {
		f, err := findings.LoadFinding(c, findingID)
		if err != nil {
			return validation.VNull(), err
		}
		f = setDeep(f, validation.VStr("DUPLICATE"), "status")
		f = setDeep(f, validation.VStr(ofFindingID), "dedup", "duplicate_of")
		if err := findings.SaveFinding(c, &f); err != nil {
			return validation.VNull(), err
		}
		return f, nil
	})
	SetFlagPossibleDuplicate(func(c *state.Campaign, findingID,
		ofFindingID string) (validation.Value, error) {
		f, err := findings.LoadFinding(c, findingID)
		if err != nil {
			return validation.VNull(), err
		}
		ids := valueStrings(getDeep(f, "dedup", "possible_duplicate_of"))
		if !slices.Contains(ids, ofFindingID) {
			ids = append(ids, ofFindingID)
		}
		f = setDeep(f, strArray(ids), "dedup", "possible_duplicate_of")
		if err := findings.SaveFinding(c, &f); err != nil {
			return validation.VNull(), err
		}
		data := validation.VObj(kv("of", validation.VStr(ofFindingID)))
		if _, err := c.Log("finding.possible_duplicate", &findingID, &data); err != nil {
			return validation.VNull(), err
		}
		return f, nil
	})
	SetFoldIntoLineage(func(c *state.Campaign, findingID, lineageID string) (validation.Value, error) {
		f, err := findings.LoadFinding(c, findingID)
		if err != nil {
			return validation.VNull(), err
		}
		f = setDeep(f, validation.VStr(lineageID), "dedup", "lineage_id")
		if err := findings.SaveFinding(c, &f); err != nil {
			return validation.VNull(), err
		}
		return f, nil
	})
	t.Cleanup(func() {
		SetMarkDuplicate(nil)
		SetFlagPossibleDuplicate(nil)
		SetFoldIntoLineage(nil)
	})
}

// ---- assertion helpers ------------------------------------------------------

// tok is one id → placeholder substitution, the form the Python twin's
// canonical report templates use (<A>, <B>, <C>, <LIN>).
type tok struct{ id, name string }

func fid(f validation.Value) string { return validation.ObjStr(f, "finding_id") }

// assertCanon compares the compact canonical JSON of v (Python's
// json.dumps(sort_keys=True, separators=(",", ":"))) against a template
// generated by the Python twin.
func assertCanon(t *testing.T, label string, v validation.Value, want string, toks ...tok) {
	t.Helper()
	got := validation.CanonCompact(v)
	for _, tk := range toks {
		got = strings.ReplaceAll(got, tk.id, tk.name)
	}
	if got != want {
		t.Fatalf("%s canon mismatch:\n got: %s\nwant: %s", label, got, want)
	}
}

// wantErr asserts err is non-nil and carries exactly the Python message.
func wantErr(t *testing.T, label string, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error %q, got nil", label, want)
	}
	if err.Error() != want {
		t.Fatalf("%s: error %q, want %q", label, err.Error(), want)
	}
}

// eventTypes is the ordered event-type list from the campaign log.
func eventTypes(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, validation.ObjStr(e, "type"))
	}
	return out
}

func lastEvent(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("no events")
	}
	return evs[len(evs)-1]
}

// ---- ported tests: tests/test_dedup_determinism.py --------------------------

func TestRepeatedSweepsAreIdempotent(t *testing.T) {
	wireSeams(t)
	c := dedupCamp(t)
	a := hypo(t, c, "First discovery of the rounding flaw")
	b := hypo(t, c, "Second discovery of the rounding flaw") // same technical signature
	first, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "first sweep", first,
		`{"cross_snapshot_flags":[],"tier1_merges":[{"kept":"<A>","merged":"<B>",`+
			`"signature":"48b7907d5bb641e3"}],"tier2_clusters":[],"tier3_flags":[],`+
			`"untouched":1}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"})
	second, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "second sweep", second,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[],"untouched":1}`)
	// the merged twin is terminal; a third sweep still adds nothing
	third, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "third sweep", third,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[],"untouched":1}`)
	kept, err := findings.LoadFinding(c, fid(a))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(kept, "status") != "HYPOTHESIS" {
		t.Fatalf("earliest finding status = %q, want HYPOTHESIS", validation.ObjStr(kept, "status"))
	}
}

func TestEarliestCreatedFindingIsKept(t *testing.T) {
	wireSeams(t)
	c := dedupCamp(t)
	a := hypo(t, c, "Earliest report of the rounding flaw")
	b := hypo(t, c, "Latest report of the rounding flaw")
	// ingest stamps created_at at microsecond resolution; force a strict order
	for _, pair := range []struct {
		f  validation.Value
		ts string
	}{{a, "2026-01-01T00:00:00Z"}, {b, "2026-01-02T00:00:00Z"}} {
		rec, err := findings.LoadFinding(c, fid(pair.f))
		if err != nil {
			t.Fatal(err)
		}
		rec = setDeep(rec, validation.VStr(pair.ts), "created_at")
		if err := findings.SaveFinding(c, &rec); err != nil {
			t.Fatal(err)
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "earliest report", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[{"kept":"<A>","merged":"<B>",`+
			`"signature":"48b7907d5bb641e3"}],"tier2_clusters":[],"tier3_flags":[],`+
			`"untouched":1}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"})
	merges := validation.ObjAt(report, "tier1_merges").A
	if len(merges) != 1 || validation.ObjStr(merges[0], "kept") != fid(a) ||
		validation.ObjStr(merges[0], "merged") != fid(b) {
		t.Fatalf("tier1_merges = %s, want kept=%s merged=%s",
			validation.CanonCompact(validation.ObjAt(report, "tier1_merges")), fid(a), fid(b))
	}
}

func TestLineageIDIsStableAcrossRuns(t *testing.T) {
	wireSeams(t)
	c := dedupCamp(t)
	a := hypo(t, c, "One report of the oracle flaw")
	b := hypoAt(t, c, "Two report of the oracle flaw", "oracle-manipulation",
		"src/Oracle2.sol", "getPrice2")
	sig := "root-cause-signature-under-test"
	for _, f := range []validation.Value{a, b} {
		if _, err := SetRootCauseSignature(c, fid(f), sig, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	clusters := validation.ObjAt(first, "tier2_clusters").A
	if len(clusters) == 0 {
		t.Fatal("same root cause should cluster")
	}
	lin1 := validation.ObjStr(clusters[0], "lineage_id")
	assertCanon(t, "first sweep cluster", first,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":`+
			`[{"auto_merged":[],"lineage_id":"<LIN>","members":["<A>","<B>"]}],`+
			`"tier3_flags":[],"untouched":2}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"}, tok{lin1, "<LIN>"})
	second, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	lin2 := validation.ObjStr(validation.ObjAt(second, "tier2_clusters").A[0], "lineage_id")
	if lin1 != lin2 {
		t.Fatalf("lineage id churned between sweeps: %q != %q", lin1, lin2)
	}
	if got := validation.ObjAt(validation.ObjAt(second, "tier2_clusters").A[0], "members").A; len(got) != 2 {
		t.Fatalf("cluster members = %d, want 2", len(got))
	}
}

// ---- ported tests: tests/test_findings.py dedup slice -----------------------

// Port of tests/test_findings.py::test_tier1_auto_merge.
func TestTier1AutoMerge(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoVault(t, c, "User can withdraw more than deposited via rounding",
		"precision-rounding")
	// morph §7.5: the second finding must be a DISTINCT claim (the ingest
	// door folds an identical payload into the first), while keeping the
	// identical class/path/function this tier-1 fixture is about.
	g := hypoVault(t, c, "User can withdraw more than deposited via rounding (re-filed)",
		"precision-rounding") // identical class/path/function
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "tier1 report", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[{"kept":"<A>","merged":"<B>",`+
			`"signature":"feb7d9e440f86a71"}],"tier2_clusters":[],"tier3_flags":[],`+
			`"untouched":1}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"})
	statuses := map[string]string{}
	dedups := map[string]validation.Value{}
	for _, x := range []validation.Value{f, g} {
		rec, err := findings.LoadFinding(c, fid(x))
		if err != nil {
			t.Fatal(err)
		}
		statuses[fid(x)] = validation.ObjStr(rec, "status")
		dedups[fid(x)] = validation.ObjAt(rec, "dedup")
	}
	if statuses[fid(f)] != "HYPOTHESIS" || statuses[fid(g)] != "DUPLICATE" {
		t.Fatalf("statuses = %v, want earliest HYPOTHESIS and later DUPLICATE", statuses)
	}
	if got := validation.ObjStr(dedups[fid(g)], "duplicate_of"); got != fid(f) {
		t.Fatalf("duplicate_of = %q, want %q", got, fid(f))
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "dup dedup", dedups[fid(g)],
		`{"content_sha":"12a56c0a98c30b02","duplicate_of":"<A>",`+
			`"technical_signature":"feb7d9e440f86a71"}`,
		tok{fid(f), "<A>"})
	assertCanon(t, "kept dedup", dedups[fid(f)],
		`{"content_sha":"b733abea37393f1e","technical_signature":"feb7d9e440f86a71"}`)
}

// Port of tests/test_findings.py::test_tier3_flag_never_auto_merges.
func TestTier3FlagNeverAutoMerges(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoVault(t, c, "User can withdraw more than deposited via rounding",
		"precision-rounding")
	g := hypoVault(t, c, "User can withdraw more than deposited via rounding",
		"logic-error")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetEconomicSignature(c, fid(x), "attacker withdraws unbacked value"); err != nil {
			t.Fatal(err)
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "tier3 report", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[{"a":"<A>","b":"<B>","signature":"3b7b159a6831ef2d"}],`+
			`"untouched":2}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"})
	a, err := findings.LoadFinding(c, fid(f))
	if err != nil {
		t.Fatal(err)
	}
	b, err := findings.LoadFinding(c, fid(g))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(a, "status") != "HYPOTHESIS" || validation.ObjStr(b, "status") != "HYPOTHESIS" {
		t.Fatalf("tier-3 must never auto-merge: statuses %q/%q",
			validation.ObjStr(a, "status"), validation.ObjStr(b, "status"))
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "flagged a", validation.ObjAt(a, "dedup"),
		`{"content_sha":"b733abea37393f1e","economic_signature":"3b7b159a6831ef2d",`+
			`"possible_duplicate_of":["<B>"],"technical_signature":"feb7d9e440f86a71"}`,
		tok{fid(g), "<B>"})
	if ids := valueStrings(getDeep(b, "dedup", "possible_duplicate_of")); !slices.Contains(ids, fid(f)) {
		t.Fatalf("b.possible_duplicate_of = %v, want %s", ids, fid(f))
	}
}

// Port of tests/test_findings.py::test_incompatible_classes_never_tier3.
func TestIncompatibleClassesNeverTier3(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoVault(t, c, "User can withdraw more than deposited via rounding",
		"precision-rounding")
	g := hypoVault(t, c, "User can withdraw more than deposited via rounding",
		"dos-griefing")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetEconomicSignature(c, fid(x), "attacker withdraws unbacked value"); err != nil {
			t.Fatal(err)
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "incompatible report", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[],"untouched":2}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"})
	a, err := findings.LoadFinding(c, fid(f))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(a, "dedup").Kind != validation.Obj {
		t.Fatal("dedup must stay an object")
	}
	if ids := valueStrings(getDeep(a, "dedup", "possible_duplicate_of")); len(ids) != 0 {
		t.Fatalf("possible_duplicate_of = %v, want none", ids)
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "incompatible a", validation.ObjAt(a, "dedup"),
		`{"content_sha":"b733abea37393f1e","economic_signature":"3b7b159a6831ef2d",`+
			`"technical_signature":"feb7d9e440f86a71"}`)
}

// ---- vector tests (byte-exact against the Python twin) ----------------------

// TestClassesCompatibleMatrix pins classes_compatible against the full 21×21
// matrix generated from the Python twin (rows are '1'/'0' bitstrings).
func TestClassesCompatibleMatrix(t *testing.T) {
	classes := []string{
		"oracle-manipulation", "flash-loan", "economic-invariant",
		"share-price-inflation", "precision-rounding", "token-integration",
		"logic-error", "access-control", "authorization", "upgrade-initializer",
		"centralization-risk", "signature-replay", "reentrancy",
		"unchecked-external-call", "dos-griefing", "bridge-message",
		"cross-chain-replay", "liquidation-logic", "donation", "unknown-class", "",
	}
	rows := []string{
		"111111100000000001000", "111111100000000000000",
		"111111100000000001000", "111111100000000000000",
		"111111100000000000000", "111111100000000000000",
		"111111100000111000000", "000000011111000000000",
		"000000011111000000000", "000000011111000000000",
		"000000011111000000000", "000000011111000110000",
		"000000100000111000000", "000000100000111000000",
		"000000100000111000000", "000000000001000110000",
		"000000000001000110000", "101000000000000001000",
		"000000000000000000100", "000000000000000000010",
		"000000000000000000001",
	}
	if len(classes) != len(rows) {
		t.Fatalf("fixture rows = %d, want %d", len(rows), len(classes))
	}
	for i, classA := range classes {
		row := make([]byte, 0, len(classes))
		for _, classB := range classes {
			if ClassesCompatible(classA, classB) {
				row = append(row, '1')
			} else {
				row = append(row, '0')
			}
		}
		if string(row) != rows[i] {
			t.Fatalf("compat row %q:\n got: %s\nwant: %s", classA, row, rows[i])
		}
	}
	// a class is always compatible with itself, even an unknown one; an
	// unknown class is compatible with nothing else
	if !ClassesCompatible("donation", "donation") {
		t.Fatal("same class must be compatible")
	}
	if ClassesCompatible("donation", "logic-error") || ClassesCompatible("", "oracle-manipulation") {
		t.Fatal("unrelated classes must not be compatible")
	}
}

func TestLineageIDVectors(t *testing.T) {
	cases := []struct {
		sig  string
		ids  []string
		want string
	}{
		{"root-cause-signature-under-test", []string{"F-000000000001", "F-000000000002"}, "LIN-f474b76f"},
		{"root-cause-signature-under-test", []string{"F-000000000002", "F-000000000001"}, "LIN-f474b76f"},
		{"sig", []string{}, "LIN-51d9c207"},
		{"sig", []string{"F-000000000002"}, "LIN-5420a465"},
		{"", []string{"F-000000000001"}, "LIN-5a4a12c1"},
		{"  Mixed  Case  Sig  ", []string{"F-b", "F-a", "F-c"}, "LIN-549dbaa3"},
		{"caf\u00e9 \u00e0 r\u00e9sum\u00e9", []string{"F-\u00e9", "F-a"}, "LIN-f6aa3f58"},
		{"dup", []string{"F-a", "F-a", "F-b"}, "LIN-0cc75fd7"},
	}
	for _, c := range cases {
		if got := LineageIDFor(c.sig, c.ids); got != c.want {
			t.Errorf("LineageIDFor(%q, %v) = %q, want %q", c.sig, c.ids, got, c.want)
		}
	}
	// member order and duplicates do not change the id
	first := LineageIDFor("sig", []string{"F-b", "F-a", "F-c"})
	if second := LineageIDFor("sig", []string{"F-c", "F-a", "F-b"}); first != second {
		t.Fatalf("member order changed the id: %q != %q", first, second)
	}
}

func TestSetRootCauseSignatureShapes(t *testing.T) {
	c := dedupCamp(t)
	f := hypo(t, c, "Signature shape probe")
	cwe := "CWE-682"
	got, err := SetRootCauseSignature(c, fid(f), "Normalized  Sentence  Here", &cwe)
	if err != nil {
		t.Fatal(err)
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "root cause dedup", validation.ObjAt(got, "dedup"),
		`{"content_sha":"3e499571a8f4d7d4","root_cause_signature":"25fb8f4a8ed723de",`+
			`"technical_signature":"48b7907d5bb641e3"}`)
	assertCanon(t, "root cause meta", validation.ObjAt(got, "dedup_meta"),
		`{"root_cause_sentence":"Normalized  Sentence  Here"}`)
	if got := validation.ObjStr(validation.ObjAt(got, "root_cause"), "cwe"); got != "CWE-682" {
		t.Fatalf("cwe = %q, want CWE-682", got)
	}
	// a falsy cwe ("" is Python-falsy) leaves the existing cwe in place
	empty := ""
	got, err = SetRootCauseSignature(c, fid(f), "Second  Sentence", &empty)
	if err != nil {
		t.Fatal(err)
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "second root cause dedup", validation.ObjAt(got, "dedup"),
		`{"content_sha":"3e499571a8f4d7d4","root_cause_signature":"306557b4f21046c0",`+
			`"technical_signature":"48b7907d5bb641e3"}`)
	assertCanon(t, "second root cause meta", validation.ObjAt(got, "dedup_meta"),
		`{"root_cause_sentence":"Second  Sentence"}`)
	if got := validation.ObjStr(validation.ObjAt(got, "root_cause"), "cwe"); got != "CWE-682" {
		t.Fatalf("falsy cwe overwrote the value: %q", got)
	}
	// nil cwe is the same falsy case
	got, err = SetRootCauseSignature(c, fid(f), "Third  Sentence", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(got, "root_cause"), "cwe"); got != "CWE-682" {
		t.Fatalf("nil cwe overwrote the value: %q", got)
	}
	if types := eventTypes(t, c); types[len(types)-1] != "dedup.root_cause_set" {
		t.Fatalf("last event = %q, want dedup.root_cause_set", types[len(types)-1])
	}
}

func TestSetEconomicSignatureShape(t *testing.T) {
	c := dedupCamp(t)
	f := hypo(t, c, "Signature shape probe")
	got, err := SetEconomicSignature(c, fid(f), "attacker drains the pool")
	if err != nil {
		t.Fatal(err)
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "economic dedup", validation.ObjAt(got, "dedup"),
		`{"content_sha":"3e499571a8f4d7d4","economic_signature":"a04e53361f4e929f",`+
			`"technical_signature":"48b7907d5bb641e3"}`)
	assertCanon(t, "economic meta", validation.ObjAt(got, "dedup_meta"),
		`{"economic_effect_sentence":"attacker drains the pool"}`)
	types := eventTypes(t, c)
	if len(types) < 2 || types[len(types)-1] != "dedup.economic_set" {
		t.Fatalf("last event = %v, want ...dedup.economic_set", types)
	}
}

func TestCrossSnapshotTier1Flag(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	a := hypo(t, c, "Cross snapshot A finding")
	b := hypo(t, c, "Cross snapshot B finding")
	rec, err := findings.LoadFinding(c, fid(b))
	if err != nil {
		t.Fatal(err)
	}
	rec = setDeep(rec, validation.VStr("SNAP-deadbeef"), "snapshot_ids", "source")
	if err := findings.SaveFinding(c, &rec); err != nil {
		t.Fatal(err)
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "cross report", report,
		`{"cross_snapshot_flags":[{"flagged":"<B>","kept":"<A>"}],"tier1_merges":[],`+
			`"tier2_clusters":[],"tier3_flags":[],"untouched":2}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"})
	// flagged, not merged: the duplicate stays LIVE and is only flagged
	flagged, err := findings.LoadFinding(c, fid(b))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(flagged, "status") != "HYPOTHESIS" {
		t.Fatalf("cross-snapshot dup status = %q, want HYPOTHESIS", validation.ObjStr(flagged, "status"))
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "cross dedup", validation.ObjAt(flagged, "dedup"),
		`{"content_sha":"f7a492781b89b1fa","possible_duplicate_of":["<A>"],`+
			`"technical_signature":"48b7907d5bb641e3"}`,
		tok{fid(a), "<A>"})
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	last := evs[len(evs)-1]
	flagEv := evs[len(evs)-2]
	if validation.ObjStr(flagEv, "type") != "dedup.cross_snapshot_flagged" ||
		validation.ObjStr(flagEv, "ref") != fid(b) {
		t.Fatalf("flag event = %s", validation.CanonCompact(flagEv))
	}
	assertCanon(t, "flag event data", validation.ObjAt(flagEv, "data"), `{"of":"<A>"}`, tok{fid(a), "<A>"})
	assertCanon(t, "run event data", validation.ObjAt(last, "data"),
		`{"tier1":0,"tier2_clusters":0,"tier3_flags":0}`)
}

func TestTier2SameSpotAutoMerges(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoAt(t, c, "Tier two same spot A", "precision-rounding",
		"src/Vault.sol", "withdraw")
	g := hypoAt(t, c, "Tier two same spot B", "logic-error", "src/Vault.sol",
		"withdraw")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetRootCauseSignature(c, fid(x), "shared root cause", nil); err != nil {
			t.Fatal(err)
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	lin := validation.ObjStr(validation.ObjAt(report, "tier2_clusters").A[0], "lineage_id")
	assertCanon(t, "tier2 same spot", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":`+
			`[{"auto_merged":["<B>"],"lineage_id":"<LIN>","members":["<A>","<B>"]}],`+
			`"tier3_flags":[],"untouched":1}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"}, tok{lin, "<LIN>"})
	dup, err := findings.LoadFinding(c, fid(g))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(dup, "status") != "DUPLICATE" || validation.ObjStr(validation.ObjAt(dup, "dedup"), "duplicate_of") != fid(f) {
		t.Fatalf("tier2 same-spot dup = %s", validation.CanonCompact(dup))
	}
}

func TestTier2SameSpotStaleSnapshotClustersOnly(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoAt(t, c, "Tier two stale A", "precision-rounding", "src/Vault.sol",
		"withdraw")
	g := hypoAt(t, c, "Tier two stale B", "logic-error", "src/Vault.sol",
		"withdraw")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetRootCauseSignature(c, fid(x), "shared root cause", nil); err != nil {
			t.Fatal(err)
		}
	}
	rec, err := findings.LoadFinding(c, fid(g))
	if err != nil {
		t.Fatal(err)
	}
	rec = setDeep(rec, validation.VStr("SNAP-deadbeef"), "snapshot_ids", "source")
	if err := findings.SaveFinding(c, &rec); err != nil {
		t.Fatal(err)
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	lin := validation.ObjStr(validation.ObjAt(report, "tier2_clusters").A[0], "lineage_id")
	// tier-2 records NO cross-snapshot flag (the asymmetry with tier 1)
	assertCanon(t, "tier2 stale", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":`+
			`[{"auto_merged":[],"lineage_id":"<LIN>","members":["<A>","<B>"]}],`+
			`"tier3_flags":[],"untouched":2}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"}, tok{lin, "<LIN>"})
	still, err := findings.LoadFinding(c, fid(g))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(still, "status") != "HYPOTHESIS" {
		t.Fatalf("stale tier2 dup status = %q, want HYPOTHESIS", validation.ObjStr(still, "status"))
	}
}

func TestTier3StaleSnapshotSkipsFlag(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoAt(t, c, "Tier three stale A", "precision-rounding", "src/Vault.sol",
		"withdraw")
	g := hypoAt(t, c, "Tier three stale B", "logic-error", "src/Vault.sol",
		"withdraw")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetEconomicSignature(c, fid(x), "attacker withdraws unbacked value"); err != nil {
			t.Fatal(err)
		}
	}
	rec, err := findings.LoadFinding(c, fid(g))
	if err != nil {
		t.Fatal(err)
	}
	rec = setDeep(rec, validation.VStr("SNAP-deadbeef"), "snapshot_ids", "source")
	if err := findings.SaveFinding(c, &rec); err != nil {
		t.Fatal(err)
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "tier3 stale", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[],"untouched":2}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"})
	live, err := findings.LoadFinding(c, fid(f))
	if err != nil {
		t.Fatal(err)
	}
	if ids := valueStrings(getDeep(live, "dedup", "possible_duplicate_of")); len(ids) != 0 {
		t.Fatalf("stale pair was flagged: %v", ids)
	}
}

// ---- resolve_candidate ------------------------------------------------------

// flaggedPair builds the tier-3 fixture: two compatible-class findings sharing
// one economic signature, swept once so both sides carry the flag.
func flaggedPair(t *testing.T, c *state.Campaign) (validation.Value, validation.Value) {
	t.Helper()
	f := hypo(t, c, "Candidate G finding")
	g := hypoAt(t, c, "Candidate H finding", "logic-error", "src/Oracle.sol", "getPrice")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetEconomicSignature(c, fid(x), "same economic effect"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RunDedup(c, true); err != nil {
		t.Fatal(err)
	}
	return f, g
}

func TestResolveCandidateRejectsBadVerdictAndUnknownFlag(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f, g := flaggedPair(t, c)
	_, err := ResolveCandidate(c, fid(f), fid(g), "maybe", "", "critic")
	wantErr(t, "bad verdict", err, "verdict must be 'same' or 'distinct', got 'maybe'")
	// Python raises KeyError(inner); str(KeyError) is repr(inner), quotes and all
	_, err = ResolveCandidate(c, fid(f), "F-ffffffffffff", "same", "", "critic")
	want := `"` + fid(f) + ` has no candidate flag for 'F-ffffffffffff'; run the dedup sweep first"`
	wantErr(t, "unknown flag", err, want)
}

func TestResolveCandidateRejectsShortNote(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f, g := flaggedPair(t, c)
	_, err := ResolveCandidate(c, fid(f), fid(g), "distinct", "no", "critic")
	wantErr(t, "short note", err, "a candidate verdict note, when given, must be substantive")
	// whitespace-only strips to nothing: same rejection
	_, err = ResolveCandidate(c, fid(f), fid(g), "distinct", "  \t ", "critic")
	wantErr(t, "blank note", err, "a candidate verdict note, when given, must be substantive")
}

func TestResolveCandidateDistinctRecordsBothSides(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f, g := flaggedPair(t, c)
	got, err := ResolveCandidate(c, fid(f), fid(g), "distinct", "", "pytest")
	if err != nil {
		t.Fatal(err)
	}
	// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
	assertCanon(t, "returned side", validation.ObjAt(got, "dedup"),
		`{"candidate_verdicts":{"<B>":"distinct"},"content_sha":"d0cb2041963342f9",`+
			`"economic_signature":"b9c34f97454df07d","possible_duplicate_of":["<B>"],`+
			`"technical_signature":"48b7907d5bb641e3"}`,
		tok{fid(g), "<B>"})
	for _, pair := range []struct {
		label string
		f     validation.Value
		tk    tok
		want  string
	}{
		// morph §7.5: ingest now stamps dedup.content_sha (the idempotency key).
		{"a side", f, tok{fid(g), "<B>"},
			`{"candidate_verdicts":{"<B>":"distinct"},"content_sha":"d0cb2041963342f9",` +
				`"economic_signature":"b9c34f97454df07d","possible_duplicate_of":["<B>"],` +
				`"technical_signature":"48b7907d5bb641e3"}`},
		{"b side", g, tok{fid(f), "<A>"},
			`{"candidate_verdicts":{"<A>":"distinct"},"content_sha":"5e000d92dfd30c03",` +
				`"economic_signature":"b9c34f97454df07d","possible_duplicate_of":["<A>"],` +
				`"technical_signature":"b25d0bf93e92e3c0"}`},
	} {
		rec, err := findings.LoadFinding(c, fid(pair.f))
		if err != nil {
			t.Fatal(err)
		}
		if validation.ObjStr(rec, "status") != "HYPOTHESIS" {
			t.Fatalf("%s status = %q, want HYPOTHESIS (distinct leaves both open)",
				pair.label, validation.ObjStr(rec, "status"))
		}
		assertCanon(t, pair.label, validation.ObjAt(rec, "dedup"), pair.want, pair.tk)
	}
	last := lastEvent(t, c)
	if validation.ObjStr(last, "type") != "dedup.candidate_resolved" || validation.ObjStr(last, "ref") != fid(f) {
		t.Fatalf("resolve event = %s", validation.CanonCompact(last))
	}
	assertCanon(t, "resolve event data", validation.ObjAt(last, "data"),
		`{"actor":"pytest","of":"<B>","verdict":"distinct"}`, tok{fid(g), "<B>"})
}

func TestResolveCandidateSameMergesYounger(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f, g := flaggedPair(t, c) // f is created first, so g is the younger side
	if _, err := ResolveCandidate(c, fid(f), fid(g), "same", "", "critic"); err != nil {
		t.Fatal(err)
	}
	older, err := findings.LoadFinding(c, fid(f))
	if err != nil {
		t.Fatal(err)
	}
	younger, err := findings.LoadFinding(c, fid(g))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(older, "status") != "HYPOTHESIS" {
		t.Fatalf("older status = %q, want HYPOTHESIS", validation.ObjStr(older, "status"))
	}
	if validation.ObjStr(younger, "status") != "DUPLICATE" ||
		validation.ObjStr(validation.ObjAt(younger, "dedup"), "duplicate_of") != fid(f) {
		t.Fatalf("younger = %s, want DUPLICATE of %s",
			validation.CanonCompact(younger), fid(f))
	}
	// an already-DUPLICATE younger side makes the merge a no-op, not an error
	if _, err := ResolveCandidate(c, fid(f), fid(g), "same", "", "critic"); err != nil {
		t.Fatal(err)
	}
	again, err := findings.LoadFinding(c, fid(g))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(again, "status") != "DUPLICATE" {
		t.Fatalf("second verdict changed the status to %q", validation.ObjStr(again, "status"))
	}
}

// TestResolveCandidateNoteRecordsOnBothSides is the D14 regression: the
// reference (and this port before the fix) rejected a valid --note because
// dedup_meta declared string-only additionalProperties while candidate_notes
// is written as a dict. The schema now declares candidate_notes as a string
// map, so a substantive note records cleanly on BOTH sides.
func TestResolveCandidateNoteRecordsOnBothSides(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f, g := flaggedPair(t, c)
	const note = "a substantive note"
	if _, err := ResolveCandidate(c, fid(f), fid(g), "distinct", note, "critic"); err != nil {
		t.Fatalf("a valid note must now record (D14 fixed): %v", err)
	}
	for _, rec := range []string{fid(f), fid(g)} {
		other := fid(g)
		if rec == other {
			other = fid(f)
		}
		loaded, err := findings.LoadFinding(c, rec)
		if err != nil {
			t.Fatal(err)
		}
		got := validation.ObjStr(validation.ObjAt(validation.ObjAt(loaded, "dedup_meta"), "candidate_notes"), other)
		if got != note {
			t.Fatalf("candidate_notes[%s] = %q, want %q", other, got, note)
		}
	}
}

// ---- G1 corroboration -------------------------------------------------------

// idOf returns the finding_id string of a finding value.
func idOf(v validation.Value) string { return validation.ObjStr(v, "finding_id") }

// reloadID loads a finding from disk, failing the test on error.
func reloadID(t *testing.T, c *state.Campaign, id string) validation.Value {
	t.Helper()
	f, err := findings.LoadFinding(c, id)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// attachTools records provenance.sast_tools = [tool] on a finding (load,
// SetOrAppend via setDeep, save) and returns the saved value.
func attachTools(t *testing.T, c *state.Campaign, f validation.Value,
	tool string) validation.Value {
	t.Helper()
	loaded, err := findings.LoadFinding(c, fid(f))
	if err != nil {
		t.Fatal(err)
	}
	tooled := setDeep(loaded, strArray([]string{tool}), "provenance", "sast_tools")
	if err := findings.SaveFinding(c, &tooled); err != nil {
		t.Fatal(err)
	}
	return tooled
}

// setupPair builds the tier-3 flagged pair with exactly one SAST side: f is
// model-flagged (no provenance at all), toolF carries
// provenance.sast_tools = ["slither:reentrancy-eth"].
func setupPair(t *testing.T) (*state.Campaign, validation.Value, validation.Value) {
	t.Helper()
	wireSeams(t)
	c := pinnedCamp(t)
	f, g := flaggedPair(t, c)
	toolF := attachTools(t, c, g, "slither:reentrancy-eth")
	return c, f, toolF
}

// setupPairUntooled builds the same flagged pair with neither side carrying
// provenance.sast_tools.
func setupPairUntooled(t *testing.T) (*state.Campaign, validation.Value, validation.Value) {
	t.Helper()
	wireSeams(t)
	c := pinnedCamp(t)
	f, g := flaggedPair(t, c)
	return c, f, g
}

func TestResolveSameRecordsCorroboration(t *testing.T) {
	c, f, toolF := setupPair(t) // f model-flagged (no sast_tools), toolF has provenance.sast_tools
	if _, err := ResolveCandidate(c, validation.ObjStr(f, "finding_id"), validation.ObjStr(toolF, "finding_id"),
		"same", "", "operator"); err != nil {
		t.Fatal(err)
	}
	// `same` merges the younger side: reload BOTH ids; the corroboration
	// record must exist on whichever survives (the non-tool side).
	reloaded := reloadID(t, c, idOf(f))
	corr := getDeep(reloaded, "dedup_meta", "corroborated_by")
	if corr.Kind != validation.Str || corr.S != validation.ObjStr(toolF, "finding_id") {
		t.Fatalf("corroborated_by not recorded on the model side: %s", validation.CanonCompact(corr))
	}
}

// TestResolveSameRecordsCorroborationWhenToolSideOlder is the reversed-order
// law pin: the SAST finding is created FIRST, so pickYoungerOlder makes it the
// survivor and merges the younger model side into it. The G1 law corroborates
// ONLY the non-tool side, so a tool-side survivor gets NOTHING — no
// dedup_meta.corroborated_by, and no dedup.corroborated event. The
// corroboration dies with the duplicate (merged-away) record, by design:
// records are only written where a consumer can read them.
func TestResolveSameRecordsCorroborationWhenToolSideOlder(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	older, younger := flaggedPair(t, c) // older is created first
	toolF := attachTools(t, c, older, "slither:reentrancy-eth")
	if _, err := ResolveCandidate(c, idOf(toolF), idOf(younger),
		"same", "", "operator"); err != nil {
		t.Fatal(err)
	}
	survivor := reloadID(t, c, idOf(toolF))
	if validation.ObjStr(survivor, "status") == "DUPLICATE" {
		t.Fatalf("the older tool side must survive the merge: %s",
			validation.CanonCompact(survivor))
	}
	if s := validation.ObjStr(reloadID(t, c, idOf(younger)), "status"); s != "DUPLICATE" {
		t.Fatalf("the younger model side status = %q, want DUPLICATE", s)
	}
	// Direction matters: a tool-side survivor is not the corroborated side.
	if corr := getDeep(survivor, "dedup_meta", "corroborated_by"); corr.Kind == validation.Str {
		t.Fatalf("a tool-side survivor must record no corroboration, got %s",
			validation.CanonCompact(corr))
	}
	if corr := getDeep(reloadID(t, c, idOf(younger)), "dedup_meta", "corroborated_by"); corr.Kind == validation.Str {
		t.Fatalf("the merged-away model side must record no corroboration, got %s",
			validation.CanonCompact(corr))
	}
	for _, e := range eventTypes(t, c) {
		if e == "dedup.corroborated" {
			t.Fatal("a tool-side survivor must emit no dedup.corroborated event")
		}
	}
	// ranking reads LoadLiveFindings: the surviving tool side carries nothing.
	live, err := findings.LoadLiveFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range live {
		if idOf(f) == idOf(toolF) {
			found = true
			if getDeep(f, "dedup_meta", "corroborated_by").Kind == validation.Str {
				t.Fatal("live tool-side survivor carries a corroborated_by")
			}
		}
	}
	if !found {
		t.Fatal("the tool side is not live after the merge")
	}
}

func TestResolveToolVsToolRecordsNothing(t *testing.T) {
	c, a, b := setupPair(t)
	a = attachTools(t, c, a, "slither:reentrancy-eth") // both sides SAST
	b = attachTools(t, c, b, "slither:unchecked-transfer")
	if _, err := ResolveCandidate(c, idOf(a), idOf(b), "same", "", "operator"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []validation.Value{reloadID(t, c, idOf(a)), reloadID(t, c, idOf(b))} {
		if getDeep(f, "dedup_meta", "corroborated_by").Kind == validation.Str {
			t.Fatal("tool-vs-tool is not independent corroboration")
		}
	}
}

func TestResolveDistinctRecordsNothing(t *testing.T) {
	c, f, toolF := setupPair(t)
	if _, err := ResolveCandidate(c, idOf(f), idOf(toolF),
		"distinct", "", "operator"); err != nil {
		t.Fatal(err)
	}
	if getDeep(reloadID(t, c, idOf(f)), "dedup_meta", "corroborated_by").Kind ==
		validation.Str {
		t.Fatal("a distinct verdict records no corroboration")
	}
}

func TestResolveSameWithoutAnyToolsRecordsNothing(t *testing.T) {
	c, f, other := setupPairUntooled(t) // neither side has provenance.sast_tools
	if _, err := ResolveCandidate(c, idOf(f), idOf(other), "same", "", "operator"); err != nil {
		t.Fatal(err)
	}
	if getDeep(reloadID(t, c, idOf(f)), "dedup_meta", "corroborated_by").Kind ==
		validation.Str {
		t.Fatal("no tool side -> no corroboration")
	}
}

// ---- run_dedup modes --------------------------------------------------------

func TestRunDedupNoAutoMerge(t *testing.T) {
	wireSeams(t)
	c := dedupCamp(t)
	a := hypo(t, c, "No merge A finding")
	b := hypo(t, c, "No merge B finding")
	report, err := RunDedup(c, false)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "no merge report", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[],"untouched":2}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"})
	for _, x := range []validation.Value{a, b} {
		rec, err := findings.LoadFinding(c, fid(x))
		if err != nil {
			t.Fatal(err)
		}
		if validation.ObjStr(rec, "status") != "HYPOTHESIS" {
			t.Fatalf("auto_merge=False changed a status to %q", validation.ObjStr(rec, "status"))
		}
	}
}

func TestRunDedupExcludesTerminalFindings(t *testing.T) {
	wireSeams(t)
	c := dedupCamp(t)
	a := hypo(t, c, "Terminal A finding")
	b := hypo(t, c, "Terminal B finding")
	// the Python fixture calls F.mark_duplicate; internal/findings does not
	// export it yet, so stamp the terminal state the sweep reads
	rec, err := findings.LoadFinding(c, fid(b))
	if err != nil {
		t.Fatal(err)
	}
	rec = setDeep(rec, validation.VStr("DUPLICATE"), "status")
	if err := findings.SaveFinding(c, &rec); err != nil {
		t.Fatal(err)
	}
	hypoAt(t, c, "Terminal C finding", "oracle-manipulation", "src/Other.sol", "other")
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "terminal report", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[],"untouched":2}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"})
	if got := validation.ObjAt(report, "untouched"); got.I != 2 {
		t.Fatalf("untouched = %d, want 2 (terminal findings leave the sweep)", got.I)
	}
}

func TestRunDedupCombinedTiers(t *testing.T) {
	wireSeams(t)
	c := dedupCamp(t)
	a := hypo(t, c, "First finding about rounding")
	b := hypo(t, c, "Second finding about rounding")
	cc := hypoAt(t, c, "Third finding about rounding", "logic-error",
		"src/Other.sol", "other")
	cwe := "CWE-682"
	if _, err := SetRootCauseSignature(c, fid(a), "shared root cause", &cwe); err != nil {
		t.Fatal(err)
	}
	if _, err := SetRootCauseSignature(c, fid(cc), "shared root cause", nil); err != nil {
		t.Fatal(err)
	}
	for _, x := range []validation.Value{a, cc} {
		if _, err := SetEconomicSignature(c, fid(x), "attacker gains value"); err != nil {
			t.Fatal(err)
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	lin := validation.ObjStr(validation.ObjAt(report, "tier2_clusters").A[0], "lineage_id")
	assertCanon(t, "combined report", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[{"kept":"<A>","merged":"<B>",`+
			`"signature":"48b7907d5bb641e3"}],"tier2_clusters":[{"auto_merged":[],`+
			`"lineage_id":"<LIN>","members":["<A>","<C>"]}],"tier3_flags":[{"a":"<A>",`+
			`"b":"<C>","signature":"9cdcd94c794a64d7"}],"untouched":2}`,
		tok{fid(a), "<A>"}, tok{fid(b), "<B>"}, tok{fid(cc), "<C>"}, tok{lin, "<LIN>"})
	last := lastEvent(t, c)
	if validation.ObjStr(last, "type") != "dedup.run" {
		t.Fatalf("last event = %q, want dedup.run", validation.ObjStr(last, "type"))
	}
	assertCanon(t, "run data", validation.ObjAt(last, "data"),
		`{"tier1":1,"tier2_clusters":1,"tier3_flags":1}`)
}

// TestRunDedupSeamsFailLoud: with no real findings.* helper installed, a sweep
// that needs one must fail rather than look successful.
func TestRunDedupSeamsFailLoud(t *testing.T) {
	c := dedupCamp(t)
	hypo(t, c, "Unwired merge A")
	hypo(t, c, "Unwired merge B")
	_, err := RunDedup(c, true)
	if err == nil || !strings.Contains(err.Error(), "findings.mark_duplicate is not wired") {
		t.Fatalf("tier1 seam error = %v, want mark_duplicate not wired", err)
	}
	c = dedupCamp(t)
	f := hypo(t, c, "Unwired fold A")
	g := hypoAt(t, c, "Unwired fold B", "oracle-manipulation", "src/Other.sol", "other")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetRootCauseSignature(c, fid(x), "shared root cause", nil); err != nil {
			t.Fatal(err)
		}
	}
	_, err = RunDedup(c, true)
	if err == nil || !strings.Contains(err.Error(), "findings.fold_into_lineage is not wired") {
		t.Fatalf("tier2 seam error = %v, want fold_into_lineage not wired", err)
	}
	c = dedupCamp(t)
	f = hypo(t, c, "Unwired flag A")
	g = hypoAt(t, c, "Unwired flag B", "logic-error", "src/Oracle.sol", "getPrice")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetEconomicSignature(c, fid(x), "same economic effect"); err != nil {
			t.Fatal(err)
		}
	}
	_, err = RunDedup(c, true)
	if err == nil || !strings.Contains(err.Error(), "findings.flag_possible_duplicate is not wired") {
		t.Fatalf("tier3 seam error = %v, want flag_possible_duplicate not wired", err)
	}
}

func TestRunDedupNoAutoMergeStillFoldsLineage(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoAt(t, c, "No merge cluster A", "precision-rounding", "src/Vault.sol",
		"withdraw")
	g := hypoAt(t, c, "No merge cluster B", "logic-error", "src/Oracle2.sol",
		"getPrice2")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetRootCauseSignature(c, fid(x), "shared root cause", nil); err != nil {
			t.Fatal(err)
		}
	}
	report, err := RunDedup(c, false)
	if err != nil {
		t.Fatal(err)
	}
	lin := validation.ObjStr(validation.ObjAt(report, "tier2_clusters").A[0], "lineage_id")
	assertCanon(t, "no merge cluster", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":`+
			`[{"auto_merged":[],"lineage_id":"<LIN>","members":["<A>","<B>"]}],`+
			`"tier3_flags":[],"untouched":2}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"}, tok{lin, "<LIN>"})
	// auto_merge=False suppresses the merge, never the lineage fold
	for _, x := range []validation.Value{f, g} {
		rec, err := findings.LoadFinding(c, fid(x))
		if err != nil {
			t.Fatal(err)
		}
		if got := validation.ObjStr(validation.ObjAt(rec, "dedup"), "lineage_id"); got != lin {
			t.Fatalf("%s lineage_id = %q, want %q", fid(x), got, lin)
		}
		if validation.ObjStr(rec, "status") != "HYPOTHESIS" {
			t.Fatalf("%s status = %q, want HYPOTHESIS", fid(x), validation.ObjStr(rec, "status"))
		}
	}
}

func TestTier2MergeRemovesMemberFromTier3(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f := hypoAt(t, c, "Tier two wins A", "precision-rounding", "src/Vault.sol",
		"withdraw")
	g := hypoAt(t, c, "Tier two wins B", "logic-error", "src/Vault.sol",
		"withdraw")
	for _, x := range []validation.Value{f, g} {
		if _, err := SetRootCauseSignature(c, fid(x), "shared root cause", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := SetEconomicSignature(c, fid(x), "attacker withdraws unbacked value"); err != nil {
			t.Fatal(err)
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	lin := validation.ObjStr(validation.ObjAt(report, "tier2_clusters").A[0], "lineage_id")
	assertCanon(t, "tier2 wins", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":`+
			`[{"auto_merged":["<B>"],"lineage_id":"<LIN>","members":["<A>","<B>"]}],`+
			`"tier3_flags":[],"untouched":1}`,
		tok{fid(f), "<A>"}, tok{fid(g), "<B>"}, tok{lin, "<LIN>"})
	// the tier-2 merge took the member out of the tier-3 sweep entirely
	older, err := findings.LoadFinding(c, fid(f))
	if err != nil {
		t.Fatal(err)
	}
	if ids := valueStrings(getDeep(older, "dedup", "possible_duplicate_of")); len(ids) != 0 {
		t.Fatalf("possible_duplicate_of = %v, want none", ids)
	}
}

// TestRunDedupGroupOrderIsInsertionOrder pins Python dict semantics: groups
// are reported in first-seen finding order, and pair flags follow member order.
func TestRunDedupGroupOrderIsInsertionOrder(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	f1 := hypoAt(t, c, "Order one A", "precision-rounding", "src/A.sol", "a")
	f2 := hypoAt(t, c, "Order one B", "logic-error", "src/B.sol", "b")
	f3 := hypoAt(t, c, "Order two A", "precision-rounding", "src/C.sol", "c")
	f4 := hypoAt(t, c, "Order two B", "logic-error", "src/D.sol", "d")
	for _, pair := range []struct {
		xs  []validation.Value
		sig string
	}{{[]validation.Value{f1, f2}, "root sig one"},
		{[]validation.Value{f3, f4}, "root sig two"}} {
		for _, x := range pair.xs {
			if _, err := SetRootCauseSignature(c, fid(x), pair.sig, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	clusters := validation.ObjAt(report, "tier2_clusters").A
	if len(clusters) != 2 {
		t.Fatalf("tier2 clusters = %d, want 2", len(clusters))
	}
	l1 := validation.ObjStr(clusters[0], "lineage_id")
	l2 := validation.ObjStr(clusters[1], "lineage_id")
	assertCanon(t, "cluster order", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":`+
			`[{"auto_merged":[],"lineage_id":"<L1>","members":["<A>","<B>"]},`+
			`{"auto_merged":[],"lineage_id":"<L2>","members":["<C>","<D>"]}],`+
			`"tier3_flags":[],"untouched":4}`,
		tok{fid(f1), "<A>"}, tok{fid(f2), "<B>"}, tok{fid(f3), "<C>"},
		tok{fid(f4), "<D>"}, tok{l1, "<L1>"}, tok{l2, "<L2>"})
	if l1 == l2 {
		t.Fatalf("distinct signatures produced the same lineage id %q", l1)
	}
}

func TestRunDedupTier3PairOrderIsMemberOrder(t *testing.T) {
	wireSeams(t)
	c := pinnedCamp(t)
	g1 := hypoAt(t, c, "Econ order one A", "precision-rounding", "src/E.sol", "e")
	g2 := hypoAt(t, c, "Econ order one B", "logic-error", "src/F.sol", "f")
	g3 := hypoAt(t, c, "Econ order two A", "precision-rounding", "src/G.sol", "g")
	g4 := hypoAt(t, c, "Econ order two B", "logic-error", "src/H.sol", "h")
	for _, pair := range []struct {
		xs  []validation.Value
		sig string
	}{{[]validation.Value{g1, g2}, "first economic effect"},
		{[]validation.Value{g3, g4}, "second economic effect"}} {
		for _, x := range pair.xs {
			if _, err := SetEconomicSignature(c, fid(x), pair.sig); err != nil {
				t.Fatal(err)
			}
		}
	}
	report, err := RunDedup(c, true)
	if err != nil {
		t.Fatal(err)
	}
	assertCanon(t, "flag order", report,
		`{"cross_snapshot_flags":[],"tier1_merges":[],"tier2_clusters":[],`+
			`"tier3_flags":[{"a":"<A>","b":"<B>","signature":"5df75953c4810fe9"},`+
			`{"a":"<C>","b":"<D>","signature":"3e994ab531d19e79"}],"untouched":4}`,
		tok{fid(g1), "<A>"}, tok{fid(g2), "<B>"}, tok{fid(g3), "<C>"}, tok{fid(g4), "<D>"})
	if got := len(validation.ObjAt(report, "tier3_flags").A); got != 2 {
		t.Fatalf("tier3 flags = %d, want 2", got)
	}
}

// TestSignatureOnDeadRowRefused pins critic r3: dedup-signature on a row the
// sweep will skip is inert bookkeeping — refused like adjudicate refuses it.
func TestSignatureOnDeadRowRefused(t *testing.T) {
	c := dedupCamp(t)
	fv := hypo(t, c, "Reentrancy in withdraw() drains the vault pool")
	f := validation.ObjStr(fv, "finding_id")
	if _, err := findings.Transition(c, f, "DISPROVED", "no reachable path",
		"critic", "", false); err != nil {
		t.Fatalf("disprove: %v", err)
	}
	if _, err := SetRootCauseSignature(c, f,
		"external call before state update enables reentrant drain", nil); err == nil ||
		!strings.Contains(err.Error(), "sweep only ever compares live rows") {
		t.Fatalf("dead-row signature must be refused: %v", err)
	}
	if _, err := SetEconomicSignature(c, f, "attacker extracts pool value"); err == nil {
		t.Fatal("economic signature on a dead row must be refused")
	}
}
