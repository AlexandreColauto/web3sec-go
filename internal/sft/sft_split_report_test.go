package sft

// Port of tests/test_sft_split_report.py (Task C): the cluster-aware split
// (never straddles, reaches the 15% floor, idempotent per seed, whole-cluster
// overshoot, empty no-op, drafts unpartitioned) and the mix report.

import (
	"testing"

	"websec/internal/validation"
)

// addCurated is `_ex(store, cluster, n=...)`: n curated examples sharing one
// cluster.
func addCurated(t *testing.T, cluster, taxonomy string, n int) []validation.Value {
	t.Helper()
	out := []validation.Value{}
	for i := 0; i < n; i++ {
		trace := "OBSERVATION: f() does x.\nINITIAL FRAMING: y.\n" +
			"A1 (z): q?\n  -> CONFIRMED. because w v u t s r q p n m l k j i h g\n" +
			"INVARIANT: a property that is checkable against code.\n" +
			"IMPACT: attacker extracts 5,000 tokens from the pool."
		st := validation.VObj(
			kv("bug_class", validation.VStr("cluster-"+cluster)),
			kv("claim", validation.VStr("an exploit shape unique to cluster "+
				cluster+" number "+itoa(i)+" with a distinct technique "+
				"description")),
			kv("assumptions", validation.VArr(validation.VObj(
				kv("id", validation.VStr("A1")),
				kv("text", validation.VStr(
					"a checkable proposition about the code path")),
				kv("status", validation.VStr("CONFIRMED")),
				kv("reason", validation.VStr("resolved by reading the cited "+
					"function and its callers"))))),
			kv("invariants", validation.VArr(validation.VObj(
				kv("statement", validation.VStr("a property precise enough to "+
					"be checked against code")),
				kv("status", validation.VStr("VIOLATED"))))),
			kv("expected_impact", validation.VStr("5,000 tokens extracted")),
			kv("next_test", validation.VStr("unit harness PoC")),
			kv("pivot_count", validation.VInt(0)))
		ex := validation.VObj(
			kv("source", validation.VObj(
				kv("kind", validation.VStr("synthetic")),
				kv("ref", validation.VStr(cluster+"-"+itoa(i))),
				kv("cluster", validation.VStr(cluster)))),
			kv("taxonomy", validation.VStr(taxonomy)),
			kv("status", validation.VStr("draft")),
			kv("rejection_reasons", validation.VArr()),
			kv("partition", validation.VNull()),
			kv("messages", validation.VArr(
				validation.VObj(
					kv("role", validation.VStr("system")),
					kv("content", validation.VStr(promptText(t)))),
				validation.VObj(
					kv("role", validation.VStr("user")),
					kv("content", validation.VStr("<bundle>"))),
				validation.VObj(
					kv("role", validation.VStr("assistant")),
					kv("content", validation.VStr(trace))))),
			kv("structured", st),
			kv("provenance", validation.VObj(
				kv("bundle_provenance", validation.VStr("hand-written")))),
			kv("created_at", validation.VStr("2026-07-15T00:00:00Z")))
		added, err := AddExample(ex, "draft")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UpdateExample(validation.ObjStr(added, "id"), strPtr("curated"), nil,
			nil); err != nil {
			t.Fatal(err)
		}
		out = append(out, added)
	}
	return out
}

func TestSFTSplitNeverStraddlesClusters(t *testing.T) {
	useStore(t)
	addCurated(t, "alpha", "confirmed-critical", 2)
	addCurated(t, "beta", "confirmed-critical", 3)
	addCurated(t, "gamma", "confirmed-critical", 1)
	stats, err := SplitExamples(7)
	if err != nil {
		t.Fatal(err)
	}
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	byCluster := map[string]map[string]bool{}
	for _, e := range validation.ObjAt(store, "examples").A {
		c := validation.ObjStr(validation.ObjAt(e, "source"), "cluster")
		if byCluster[c] == nil {
			byCluster[c] = map[string]bool{}
		}
		byCluster[c][validation.ObjStr(e, "partition")] = true
	}
	for c, parts := range byCluster {
		if len(parts) != 1 {
			t.Fatalf("cluster %s straddles: %v", c, parts)
		}
	}
	if validation.ObjAt(stats, "held-out").I < 1 {
		t.Fatalf("held-out = %v", validation.ObjAt(stats, "held-out"))
	}
}

func TestSFTSplitReaches15PctFloor(t *testing.T) {
	useStore(t)
	for _, c := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		addCurated(t, c, "confirmed-critical", 2) // 16 curated examples
	}
	if _, err := SplitExamples(1); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	held := 0
	for _, e := range validation.ObjAt(store, "examples").A {
		if validation.ObjStr(e, "partition") == "held-out" {
			held++
		}
	}
	if float64(held)/16.0 < 0.15 {
		t.Fatalf("held = %d/16", held)
	}
}

func TestSFTSplitIdempotentPerSeed(t *testing.T) {
	useStore(t)
	addCurated(t, "alpha", "confirmed-critical", 2)
	addCurated(t, "beta", "confirmed-critical", 3)
	s1, err := SplitExamples(42)
	if err != nil {
		t.Fatal(err)
	}
	snap1 := partitionSnapshot(t)
	s2, err := SplitExamples(42)
	if err != nil {
		t.Fatal(err)
	}
	snap2 := partitionSnapshot(t)
	if validation.CanonCompact(s1) != validation.CanonCompact(s2) {
		t.Fatalf("stats differ: %s vs %s", validation.CanonCompact(s1),
			validation.CanonCompact(s2))
	}
	if snap1 != snap2 {
		t.Fatalf("snapshots differ: %s vs %s", snap1, snap2)
	}
}

func partitionSnapshot(t *testing.T) string {
	t.Helper()
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	out := ""
	for _, e := range validation.ObjAt(store, "examples").A {
		out += validation.ObjStr(e, "id") + "=" + validation.ObjStr(e, "partition") + ";"
	}
	return out
}

func TestSFTSplitOvershootsWholeClusterButNeverSplits(t *testing.T) {
	useStore(t)
	// One giant cluster alone: it goes wholly to held-out even though that is
	// 100% — the no-straddle rule beats the 15% floor.
	addCurated(t, "solo", "confirmed-critical", 4)
	stats, err := SplitExamples(3)
	if err != nil {
		t.Fatal(err)
	}
	store, err := LoadStore()
	if err != nil {
		t.Fatal(err)
	}
	parts := map[string]bool{}
	for _, e := range validation.ObjAt(store, "examples").A {
		parts[validation.ObjStr(e, "partition")] = true
	}
	if len(parts) != 1 || !parts["held-out"] {
		t.Fatalf("parts = %v", parts)
	}
	if got := validation.ObjAt(stats, "held_out_pct").F; got != 100.0 {
		t.Fatalf("held_out_pct = %v", got)
	}
}

func TestSFTSplitEmptyStoreIsNoop(t *testing.T) {
	useStore(t)
	stats, err := SplitExamples(42)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(stats, "training").I != 0 || validation.ObjAt(stats, "held-out").I != 0 {
		t.Fatalf("stats = %v", stats)
	}
}

func TestSFTDraftsStayUnpartitioned(t *testing.T) {
	useStore(t)
	addCurated(t, "alpha", "confirmed-critical", 1)
	// A draft must still pass lint to be added (the gate applies to every
	// add); taxonomy may be null on drafts (schema allOf).
	trace := "OBSERVATION: f() does x.\nINITIAL FRAMING: y.\n" +
		"A1 (z): q?\n  -> CONFIRMED. because w v u t s r q p n m l k j i h g\n" +
		"INVARIANT: a property that is checkable against code.\n" +
		"IMPACT: attacker extracts 5,000 tokens from the pool."
	draft := validation.VObj(
		kv("source", validation.VObj(
			kv("kind", validation.VStr("synthetic")),
			kv("ref", validation.VStr("d1")),
			kv("cluster", validation.VStr("delta")))),
		kv("taxonomy", validation.VNull()),
		kv("status", validation.VStr("draft")),
		kv("rejection_reasons", validation.VArr()),
		kv("partition", validation.VNull()),
		kv("messages", validation.VArr(
			validation.VObj(
				kv("role", validation.VStr("system")),
				kv("content", validation.VStr(promptText(t)))),
			validation.VObj(
				kv("role", validation.VStr("user")),
				kv("content", validation.VStr("<b>"))),
			validation.VObj(
				kv("role", validation.VStr("assistant")),
				kv("content", validation.VStr(trace))))),
		kv("structured", validation.VObj(
			kv("bug_class", validation.VStr("draft-shape")),
			kv("claim", validation.VStr("a claim long enough to pass the "+
				"schema minimum length")),
			kv("assumptions", validation.VArr(validation.VObj(
				kv("id", validation.VStr("A1")),
				kv("text", validation.VStr(
					"a checkable proposition about the code path")),
				kv("status", validation.VStr("CONFIRMED")),
				kv("reason", validation.VStr("resolved by reading the cited "+
					"function and its callers"))))),
			kv("invariants", validation.VArr(validation.VObj(
				kv("statement", validation.VStr("a property precise enough "+
					"to be checked against code")),
				kv("status", validation.VStr("UNCHECKED"))))),
			kv("expected_impact", validation.VStr("5,000 tokens extracted")),
			kv("next_test", validation.VStr("unit harness PoC")),
			kv("pivot_count", validation.VInt(0)))),
		kv("provenance", validation.VObj(
			kv("bundle_provenance", validation.VStr("hand-written")))),
		kv("created_at", validation.VStr("2026-07-15T00:00:00Z")))
	added, err := AddExample(draft, "draft")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SplitExamples(9); err != nil {
		t.Fatal(err)
	}
	got, err := GetExample(validation.ObjStr(added, "id"))
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(got, "partition").Kind != validation.Null {
		t.Fatalf("partition = %v", validation.ObjAt(got, "partition"))
	}
}

func TestSFTMixReportOnTwoSeeds(t *testing.T) {
	repoStore(t)
	rep, err := MixReport()
	if err != nil {
		t.Fatal(err)
	}
	tm := validation.ObjAt(rep, "taxonomy_mix")
	if got := validation.ObjAt(tm, "confirmed-critical"); validation.ObjAt(got, "count").I != 1 {
		t.Fatalf("confirmed-critical = %v", got)
	}
	if got := validation.ObjAt(tm, "real-weakness-non-exploitable"); validation.ObjAt(got, "count").I != 1 {
		t.Fatalf("real-weakness = %v", got)
	}
	if got := validation.ObjAt(validation.ObjAt(tm, "confirmed-critical"), "target_pct").F; got != 40.0 {
		t.Fatalf("target_pct = %v", got)
	}
	if got := validation.ObjAt(validation.ObjAt(tm, "confirmed-critical"), "gap").F; got != 40.0-50.0 {
		t.Fatalf("gap = %v", got)
	}
	if got := validation.ObjAt(rep, "pivot_share_pct").F; got != 50.0 {
		t.Fatalf("pivot_share_pct = %v", got)
	}
	if got := validation.CanonCompact(validation.ObjAt(rep, "source_mix")); got !=
		`{"historical":2}` {
		t.Fatalf("source_mix = %s", got)
	}
	if got := validation.ObjAt(rep, "dedup_collisions").I; got != 0 {
		t.Fatalf("dedup_collisions = %d", got)
	}
	if got := validation.ObjAt(validation.ObjAt(rep, "partition_counts"), "unsplit").I; got != 2 {
		t.Fatalf("unsplit = %d", got)
	}
}

func TestSFTMixReportGapAndWarnings(t *testing.T) {
	useStore(t)
	addCurated(t, "alpha", "confirmed-critical", 1) // confirmed-critical only
	rep, err := MixReport()
	if err != nil {
		t.Fatal(err)
	}
	gap := validation.ObjAt(validation.ObjAt(validation.ObjAt(rep, "taxonomy_mix"), "invalid-hypothesis"), "gap")
	if gap.F != 20.0 {
		t.Fatalf("gap = %v", gap)
	}
	if got := validation.ObjAt(rep, "dedup_collisions").I; got != 0 {
		t.Fatalf("dedup_collisions = %d", got)
	}
}
