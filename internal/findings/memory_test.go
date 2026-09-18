package findings

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- fixtures (port of tests/test_memory_check_gate.py) ----

// globalMemoryRow is _seed_global_row's row (the exact Python dict).
func globalMemoryRow() validation.Value {
	return validation.VObj(
		kv("memory_id", validation.VStr("MEM-global01")),
		kv("campaign_id", validation.VStr("ingest:test:case")),
		kv("finding_id", validation.VNull()),
		kv("snapshot_id", validation.VNull()),
		kv("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kv("kind", validation.VStr("confirmed")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("pattern", validation.VStr("Test Pattern")),
		kv("bug_class", validation.VStr("logic-error")),
		kv("cwe", validation.VNull()),
		kv("evidence_summary", validation.VStr("Test incident.")),
		kv("partition", validation.VStr("dev")),
		kv("schema_version", validation.VInt(2)),
		kv("rejection_class", validation.VNull()),
		kv("deciding_propositions", validation.VArr()),
		kv("promotion_status", validation.VStr("promoted")),
		kv("approved_by", validation.VStr("operator")),
		kv("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
}

// campaignMemoryRow is _seed_campaign_row's row.
func campaignMemoryRow() validation.Value {
	return validation.VObj(
		kv("memory_id", validation.VStr("MEM-camp0001")),
		kv("pattern", validation.VStr("Local Pattern")),
		kv("bug_class", validation.VStr("reentrancy")),
	)
}

// installMemoryStore wires the shared/learning seams for one test (the store
// loaders themselves are another task; the finding-facing logic under test is
// the same). shared rows are handed over in the {row: ...} wrapper shape.
func installMemoryStore(t *testing.T, shared ...validation.Value) {
	t.Helper()
	prevShared, prevLearn := sharedMemoryRowsFunc, learningAllMemoryFunc
	sharedMemoryRowsFunc = func(string) ([]validation.Value, error) {
		out := make([]validation.Value, 0, len(shared))
		for _, r := range shared {
			out = append(out, validation.VObj(kv("row", r)))
		}
		return out, nil
	}
	learningAllMemoryFunc = func(*state.Campaign) ([]validation.Value, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		sharedMemoryRowsFunc, learningAllMemoryFunc = prevShared, prevLearn
	})
}

// mintFinding is _mint_finding mapped onto ingest_hypothesis.
func mintFinding(t *testing.T, c *state.Campaign, class string) validation.Value {
	t.Helper()
	f, err := IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("Untitled finding")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(class)),
			kv("description", validation.VStr("mechanism described in detail here")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("f")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ---- ported tests ----

// Port of test_visible_rows_merge_both_sources: the shared store wins, the
// learning rows fill the gaps. PORT-NOTE: the tier readers themselves
// (shared_memory/learning) are unported, so the store seam stands in.
func TestVisibleRowsMergeBothSources(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	prevLearn := learningAllMemoryFunc
	learningAllMemoryFunc = func(*state.Campaign) ([]validation.Value, error) {
		return []validation.Value{campaignMemoryRow()}, nil
	}
	defer func() { learningAllMemoryFunc = prevLearn }()
	vis, err := VisibleMemoryRows(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(vis) != 2 {
		t.Fatalf("visible rows = %d, want 2", len(vis))
	}
	if _, ok := vis["MEM-global01"]; !ok {
		t.Error("global row missing")
	}
	row, ok := vis["MEM-camp0001"]
	if !ok {
		t.Fatal("campaign row missing")
	}
	if got := validation.ObjStr(row, "bug_class"); got != "reentrancy" {
		t.Errorf("campaign row bug_class = %q, want reentrancy", got)
	}
	if got := validation.ObjStr(vis["MEM-global01"], "bug_class"); got != "logic-error" {
		t.Errorf("global row bug_class = %q, want logic-error", got)
	}
}

// Port of test_visible_rows_include_root_tier_shared_store: visible_memory_rows
// must hand the shared loader the campaign ROOT (a path), never the Campaign
// object — passing the object resolves the root tier to
// <campaign.dir>/shared-memory, where publish never writes.
func TestVisibleRowsIncludeRootTierSharedStore(t *testing.T) {
	c := ingestCamp(t)
	var gotRoot string
	prevShared := sharedMemoryRowsFunc
	sharedMemoryRowsFunc = func(root string) ([]validation.Value, error) {
		gotRoot = root
		return []validation.Value{validation.VObj(kv("row", globalMemoryRow()))}, nil
	}
	defer func() { sharedMemoryRowsFunc = prevShared }()
	vis, err := VisibleMemoryRows(c)
	if err != nil {
		t.Fatal(err)
	}
	if gotRoot != c.Root {
		t.Fatalf("load_shared_memory(root) = %q, want campaign.root %q",
			gotRoot, c.Root)
	}
	if _, ok := vis["MEM-global01"]; !ok {
		t.Fatal("root-tier row not visible")
	}
}

// Port of test_record_validates_ids_and_stamps: the stamp is the digest over
// the LIVE rows, and the entry shape is contractual.
func TestRecordValidatesIDsAndStamps(t *testing.T) {
	c := ingestCamp(t)
	row := globalMemoryRow()
	installMemoryStore(t, row)
	f := mintFinding(t, c, "logic-error")
	out, err := RecordMemoryCheck(c, validation.ObjStr(f, "finding_id"),
		[]validation.Value{validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
			kv("mode", validation.VStr("negative")),
		)})
	if err != nil {
		t.Fatal(err)
	}
	checks := validation.ObjAt(asDict(validation.ObjAt(out, "provenance")), "memory_checks")
	if len(checks.A) != 1 {
		t.Fatalf("memory_checks = %d, want 1", len(checks.A))
	}
	entry := checks.A[0]
	if ids := validation.ObjAt(entry, "memory_ids"); len(ids.A) != 1 ||
		ids.A[0].S != "MEM-global01" {
		t.Errorf("memory_ids = %v", ids)
	}
	if got := validation.ObjStr(entry, "mode"); got != "negative" {
		t.Errorf("mode = %q, want negative", got)
	}
	wantDigest := "4856491a33fd0b0665bc37ffd3c15d211f919480950b1bf5a05694fb2d7b6e10"
	got := validation.ObjStr(entry, "row_digest")
	if got != wantDigest {
		t.Fatalf("row_digest = %q, want %q", got, wantDigest)
	}
	if got != ComputeRowDigest([]string{"MEM-global01"},
		map[string]validation.Value{"MEM-global01": row}) {
		t.Error("stamp must equal compute_row_digest over the live rows")
	}
	if validation.ObjStr(entry, "consulted_at") == "" {
		t.Error("consulted_at missing")
	}
}

// Port of test_record_rejects_unknown_id.
func TestRecordRejectsUnknownID(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	f := mintFinding(t, c, "logic-error")
	_, err := RecordMemoryCheck(c, validation.ObjStr(f, "finding_id"),
		[]validation.Value{validation.VObj(
			kv("memory_ids", validation.VArr(validation.VStr("MEM-nope"))),
			kv("mode", validation.VStr("negative")),
		)})
	wantErr(t, err, "MEM-nope")
	if !strings.Contains(err.Error(), "— not in the visible store") {
		t.Fatalf("error %q misses the visible-store clause", err.Error())
	}
}

// Port of test_record_dedupes_on_ids_and_mode.
func TestRecordDedupesOnIDsAndMode(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	f := mintFinding(t, c, "logic-error")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := RecordMemoryCheck(c, fid, []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	out, err := RecordMemoryCheck(c, fid, []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr("negative")))})
	if err != nil {
		t.Fatal(err)
	}
	checks := validation.ObjAt(asDict(validation.ObjAt(out, "provenance")), "memory_checks")
	if len(checks.A) != 1 {
		t.Fatalf("duplicate check recorded: %d entries", len(checks.A))
	}
	// same ids, different mode: a distinct entry
	out, err = RecordMemoryCheck(c, fid, []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr("comparative")),
		kv("note", validation.VStr("compared X")))})
	if err != nil {
		t.Fatal(err)
	}
	checks = validation.ObjAt(asDict(validation.ObjAt(out, "provenance")), "memory_checks")
	if len(checks.A) != 2 {
		t.Fatalf("distinct mode not recorded: %d entries", len(checks.A))
	}
	if got := validation.ObjStr(checks.A[1], "note"); got != "compared X" {
		t.Errorf("note = %q, want 'compared X'", got)
	}
}

// Port of test_gate_accepts_valid_negative_check.
func TestGateAcceptsValidNegativeCheck(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	f := mintFinding(t, c, "logic-error")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := RecordMemoryCheck(c, fid, []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	fails, err := MemoryCheckFails(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if fails != nil {
		t.Fatalf("valid check rejected: %q", *fails)
	}
}

// Port of test_gate_blocks_without_check.
func TestGateBlocksWithoutCheck(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	f := mintFinding(t, c, "logic-error")
	msg, err := MemoryCheckFails(c, validation.ObjStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil || !strings.Contains(*msg, "recall") {
		t.Fatalf("missing check must block with the recall hint, got %v", msg)
	}
	want := "no verified graph-memory recall recorded — none recorded, or " +
		"every recorded check is stale (a referenced row changed or left " +
		"the store) — run `webv2 recall " + c.CampaignID + " --finding " +
		validation.ObjStr(f, "finding_id") + "`"
	if *msg != want {
		t.Fatalf("message = %q, want %q", *msg, want)
	}
	// the printed remedy must be a COMPLETE executable command: the campaign
	// positional and the finding are both present (Wave-B review follow-up;
	// Python's test_every_printed_recall_remedy_is_executable is P3/briefing).
	if !strings.Contains(*msg, "webv2 recall "+c.CampaignID+" --finding "+
		validation.ObjStr(f, "finding_id")) {
		t.Fatalf("remedy is not an executable command: %q", *msg)
	}
}

// Port of test_gate_blocks_stale_store: mutating the row after recording
// invalidates the stamp.
func TestGateBlocksStaleStore(t *testing.T) {
	c := ingestCamp(t)
	row := globalMemoryRow()
	installMemoryStore(t, row)
	f := mintFinding(t, c, "logic-error")
	fid := validation.ObjStr(f, "finding_id")
	if _, err := RecordMemoryCheck(c, fid, []validation.Value{validation.VObj(
		kv("memory_ids", validation.VArr(validation.VStr("MEM-global01"))),
		kv("mode", validation.VStr("negative")))}); err != nil {
		t.Fatal(err)
	}
	tampered := row
	tampered.O = validation.SetOrAppend(tampered.O, "evidence_summary",
		validation.VStr("TAMPERED."))
	installMemoryStore(t, tampered)
	msg, err := MemoryCheckFails(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil || !strings.Contains(*msg, "stale") {
		t.Fatalf("stale store must block, got %v", msg)
	}
}

// Port of test_gate_blocks_legacy_rag_refs: a hand-written corpus-reference
// list is NOT a memory check. Written without re-validation, the way an old
// campaign left it on disk.
func TestGateBlocksLegacyRagRefs(t *testing.T) {
	c := ingestCamp(t)
	installMemoryStore(t, globalMemoryRow())
	f := mintFinding(t, c, "logic-error")
	prov := validation.VObj(kv("rag_refs", validation.VArr(validation.VObj(
		kv("chunk_id", validation.VStr("CHUNK-1")),
		kv("mode", validation.VStr("negative")),
	))))
	f.O = validation.SetOrAppend(f.O, "provenance", prov)
	if err := validation.WriteJson(FindingPath(c, validation.ObjStr(f, "finding_id")),
		f, ""); err != nil {
		t.Fatal(err)
	}
	msg, err := MemoryCheckFails(c, validation.ObjStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("rag_refs must not satisfy the memory check")
	}
}

// ---- byte-exact digest vectors ----

func TestComputeRowDigestVectors(t *testing.T) {
	row := globalMemoryRow()
	got := ComputeRowDigest([]string{"MEM-global01"},
		map[string]validation.Value{"MEM-global01": row})
	want := "4856491a33fd0b0665bc37ffd3c15d211f919480950b1bf5a05694fb2d7b6e10"
	if got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
	// empty list -> digest of []
	if got := ComputeRowDigest(nil, map[string]validation.Value{}); got != "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" {
		t.Fatalf("empty digest = %q", got)
	}
	// _canonical_row_hash vector
	wantRowHash := "d046df4caefcb93fd96e82e6f00b97c1122654f33e4dedd93fe39e10bdef2493"
	if got := canonicalRowHash(row); got != wantRowHash {
		t.Fatalf("canonical row hash = %q, want %q", got, wantRowHash)
	}
	// an id absent from the store contributes nothing
	if got := ComputeRowDigest([]string{"MEM-nope"},
		map[string]validation.Value{}); got !=
		"4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" {
		t.Fatalf("absent id digest = %q", got)
	}
}
