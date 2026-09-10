package planner

// disposition_test.go — IMPROVEMENTS B4: the disposition linter. Pins the
// dismissal vocabulary, the high-risk row rule, the v2 gate (rejection,
// refutation backing, override + event), and the v1 review scan.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestDismissalPhrasesTable pins the B4 vocabulary: every one of the nine
// phrases is detected case-insensitively, a clean reason gets no hits, and
// multiple hits come back in table order.
func TestDismissalPhrasesTable(t *testing.T) {
	if len(DismissalPhrases) != 9 {
		t.Fatalf("vocabulary size = %d, want 9", len(DismissalPhrases))
	}
	for _, p := range DismissalPhrases {
		hits := DismissalHits("the row is " + strings.ToUpper(p) + " end")
		if len(hits) != 1 || hits[0] != p {
			t.Errorf("phrase %q: hits = %v, want [%s]", p, hits, p)
		}
	}
	if hits := DismissalHits("checked it thoroughly by hand"); len(hits) != 0 {
		t.Errorf("clean reason: hits = %v, want none", hits)
	}
	multi := DismissalHits("LIVENESS-ONLY and NO PROFIT, but no economic impact")
	want := []string{"liveness-only", "no economic impact", "no profit"}
	if len(multi) != len(want) {
		t.Fatalf("multi hits = %v, want %v", multi, want)
	}
	for i := range want {
		if multi[i] != want[i] {
			t.Errorf("multi hit %d = %q, want %q", i, multi[i], want[i])
		}
	}
}

// TestHighRiskRow pins the tier/gap rule: tier 0 or gap >= 3, with a missing
// tier reading as 0 (the fail-safe default).
func TestHighRiskRow(t *testing.T) {
	cases := []struct {
		name string
		row  validation.Value
		want bool
	}{
		{"tier0_low_gap", validation.VObj(kv("tier", validation.VInt(0)), kv("assertion_gap", validation.VInt(1))), true},
		{"tier1_gap3", validation.VObj(kv("tier", validation.VInt(1)), kv("assertion_gap", validation.VInt(3))), true},
		{"tier2_gap2", validation.VObj(kv("tier", validation.VInt(2)), kv("assertion_gap", validation.VInt(2))), false},
		{"tier5_gap10", validation.VObj(kv("tier", validation.VInt(5)), kv("assertion_gap", validation.VInt(10))), true},
		{"missing_tier_is_zero", validation.VObj(kv("assertion_gap", validation.VInt(1))), true},
		{"empty_row", validation.VObj(), true},
	}
	for _, c := range cases {
		if got := HighRiskRow(c.row); got != c.want {
			t.Errorf("%s: HighRiskRow = %v, want %v", c.name, got, c.want)
		}
	}
}

// dgRow81 is the fixture's tier-0/gap-4 row (probe assertion-strength,
// anchor consumer rendering to Rollup.sol#L45).
func dgRow81(t *testing.T) validation.Value {
	t.Helper()
	surface, _ := maSurface(t)
	for _, r := range listOf(*surface, "rows") {
		if objStr(r, "row_id") == "81dfad6492" {
			return deepCopy(t, r)
		}
	}
	t.Fatalf("row 81dfad6492 not in fixture surface")
	return validation.VNull()
}

// dgLowRow is the fixture row re-tuned to tier 2 / gap 1 (not high-risk),
// keeping every anchor field so the anchor path still resolves.
func dgLowRow(t *testing.T) validation.Value {
	row := dgRow81(t)
	row.O = setOrAppend(row.O, "row_id", validation.VStr("0000000001"))
	row.O = setOrAppend(row.O, "tier", validation.VInt(2))
	row.O = setOrAppend(row.O, "assertion_gap", validation.VInt(1))
	return row
}

// probePriorityVal builds one plan priority, optionally closed with a reason
// and referencing a probe row.
func probePriorityVal(id, status, reason, rowID string) validation.Value {
	v := validation.VObj(
		kv("id", validation.VStr(id)),
		kv("question", validation.VStr("disposition fixture row "+rowID)),
		kv("risk", validation.VFloat(0.5)),
		kv("trajectories", validation.VArr(validation.VStr("economic"))),
		kv("status", validation.VStr(status)),
	)
	if reason != "" {
		v.O = setOrAppend(v.O, "closed_reason", validation.VStr(reason))
	}
	v.O = setOrAppend(v.O, "probe", validation.VObj(
		kv("row_id", validation.VStr(rowID)),
		kv("probe_id", validation.VStr("assertion-strength")),
		kv("axis", validation.VStr("enforcement-timing")),
		kv("surface_sha", validation.VStr("0000000000000000000000000000000000000000000000000000000000000000")),
		kv("shape_sha", validation.VStr("6f498a3270b53c6e"))))
	return v
}

// TestDismissalGateMatrix pins the v2 gate: a dismissal-vocabulary closure on
// a high-risk row is rejected unless its ref is refutation-backed (an
// existing exec record or a registered invariant), and low-risk rows /
// clean reasons / blocked outcomes never trip it.
func TestDismissalGateMatrix(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dg-matrix")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	reason := "liveness-only, the owner can revert"

	// (a) no ref, no override: rejected, with the phrases + guidance
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer")})
	if err == nil {
		t.Fatal("bare dismissal on a tier-0 row must be rejected")
	}
	for _, want := range []string{"dismissal vocabulary", "'liveness-only'",
		"'owner can revert'", "EXEC-", "--override-dismissal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection %q missing %q", err, want)
		}
	}

	// (b) a file#L ref is anchor-shaped, not refutation: still rejected
	refFile := "Rollup.sol#L45"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refFile})
	if err == nil || !strings.Contains(err.Error(), "dismissal vocabulary") {
		t.Fatalf("file#L ref must not back a dismissal, err = %v", err)
	}

	// (c) an EXEC id with no record on disk: still rejected
	refGhost := "EXEC-0000000000"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refGhost})
	if err == nil || !strings.Contains(err.Error(), "dismissal vocabulary") {
		t.Fatalf("ghost EXEC ref must not back a dismissal, err = %v", err)
	}

	// (d) a real exec record on disk: the refutation backs the closure
	refExec := "EXEC-abcdef1234"
	exDir := filepath.Join(camp.ExecsDir, refExec)
	if err := os.MkdirAll(exDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exDir, "exec_record.json"),
		[]byte(`{"exec_id":"`+refExec+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refExec})
	if err != nil {
		t.Fatalf("exec-backed dismissal must pass: %v", err)
	}
	p := probePriority(t, plan, "Q-005")
	if got := objStr(p, "closed_ref"); got != refExec {
		t.Errorf("closed_ref = %q, want the refutation %q", got, refExec)
	}
	// the anchor record keeps its own citation of the field
	if got := objStr(objAt(objAt(p, "probe"), "anchor"), "ref"); got != refFile {
		t.Errorf("probe.anchor.ref = %q, want %q", got, refFile)
	}

	// (e) a registered invariant id: also backs the closure
	links := validation.VObj(kv("invariants", validation.VObj(kv("INV-1", validation.VObj(
		kv("test_status", validation.VStr("documented")),
		kv("status", validation.VStr("UNVERIFIED")),
		kv("source", validation.VStr("spec")))))))
	if err := os.MkdirAll(camp.ArtifactsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(camp.ArtifactsDir,
		"invariant_links.json"), links, ""); err != nil {
		t.Fatal(err)
	}
	reasonNA := "no economic impact"
	refInv := "INV-1"
	plan, err = MarkAnswered(camp, plan, "Q-006", "not-applicable",
		AnsweredOpts{Reason: &reasonNA, Anchor: strPtr("consumer"), Ref: &refInv})
	if err != nil {
		t.Fatalf("invariant-backed dismissal must pass: %v", err)
	}

	// (f) an INV id not in the registry: rejected
	refGhostInv := "INV-9"
	_, err = MarkAnswered(camp, plan, "Q-007", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refGhostInv})
	if err == nil || !strings.Contains(err.Error(), "dismissal vocabulary") {
		t.Fatalf("ghost INV ref must not back a dismissal, err = %v", err)
	}

	// (g) the same dismissal on a LOW-risk row (tier 2, gap 1): passes
	// without any ref or override — the gate only polices high-risk rows.
	// The plan is the schema-complete recorded plan plus one extra
	// priority on the low-risk row.
	lowRow := dgLowRow(t)
	lowSurface := validation.VObj(kv("rows", validation.VArr(lowRow)))
	withProbes(t, probeEnv{surface: &lowSurface, index: index})
	lowCamp := newCampaign(t, "dg-low")
	lowPlan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	lowPlan.O = setOrAppend(lowPlan.O, "priorities", validation.VArr(
		append(listOf(lowPlan, "priorities"),
			probePriorityVal("Q-100", "open", "", "0000000001"))...))
	if _, err := MarkAnswered(lowCamp, lowPlan, "Q-100", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer")}); err != nil {
		t.Fatalf("low-risk dismissal must pass without backing: %v", err)
	}

	// (h) blocked is not a disposition: a tier-0 row closed as blocked with
	// dismissal vocabulary never trips the gate (and needs no anchor)
	surface2, index2 := maSurface(t)
	withProbes(t, probeEnv{surface: surface2, index: index2})
	blockCamp := newCampaign(t, "dg-blocked")
	if _, err := MarkAnswered(blockCamp, deepCopy(t, maPlan(t, "plan_probe_rows.json")),
		"Q-005", "blocked", AnsweredOpts{Reason: &reason}); err != nil {
		t.Fatalf("blocked is not a disposition, err = %v", err)
	}
}

// TestDismissalGateOverride pins the override: it refuses to run without a
// reason, and with one it closes the row and logs probe.dismissal_overridden
// with the full provenance (row, tier, gap, actor, phrases, both reasons).
func TestDismissalGateOverride(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dg-override")
	reason := "not exploitable, never permanently"

	// override without a reason: refused before any state change
	_, err := MarkAnswered(camp, deepCopy(t, maPlan(t, "plan_probe_rows.json")),
		"Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true})
	if err == nil || !strings.Contains(err.Error(),
		"--override-dismissal needs --override-reason") {
		t.Fatalf("override without reason must be refused, err = %v", err)
	}

	// override with a reason: closes + logs the audit event
	why := "the owner confirmed the intended behavior in the spec"
	plan, err := MarkAnswered(camp, deepCopy(t, maPlan(t, "plan_probe_rows.json")),
		"Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true, OverrideReason: &why, Actor: "operator"})
	if err != nil {
		t.Fatalf("override with reason must pass: %v", err)
	}
	p := probePriority(t, plan, "Q-005")
	if got := objStr(p, "status"); got != "answered" {
		t.Fatalf("status = %q, want answered", got)
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found validation.Value
	for _, e := range evts {
		if objStr(e, "type") == "probe.dismissal_overridden" {
			found = e
		}
	}
	if found.Kind == validation.Null {
		t.Fatal("no probe.dismissal_overridden event logged")
	}
	data := objAt(found, "data")
	if got := objStr(data, "row_id"); got != "81dfad6492" {
		t.Errorf("event row_id = %q", got)
	}
	if got := objAt(data, "tier").I; got != 0 {
		t.Errorf("event tier = %d, want 0", got)
	}
	if got := objAt(data, "assertion_gap").I; got != 4 {
		t.Errorf("event assertion_gap = %d, want 4", got)
	}
	if got := objStr(data, "actor"); got != "operator" {
		t.Errorf("event actor = %q, want operator", got)
	}
	if got := objStr(data, "override_reason"); got != why {
		t.Errorf("event override_reason = %q", got)
	}
	if got := objStr(data, "closed_reason"); got != reason {
		t.Errorf("event closed_reason = %q", got)
	}
	phrases := listOf(data, "phrases")
	if len(phrases) != 2 || objStr(phrases[0], "") != "" ||
		phrases[0].S != "not exploitable" || phrases[1].S != "never permanently" {
		t.Errorf("event phrases = %v, want [not exploitable never permanently]",
			phrases)
	}
}

// TestDispositionReview pins the v1 scan: only high-risk CLOSED probe rows
// with dismissal vocabulary are flagged, in plan order; low-risk rows,
// clean reasons, open rows, and non-probe rows are never flagged.
func TestDispositionReview(t *testing.T) {
	surface, _ := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: nil})
	camp := newCampaign(t, "dg-review")
	plan := validation.VObj(kv("priorities", validation.VArr(
		// flagged: tier-0/gap-4 row closed with dismissal vocabulary
		probePriorityVal("Q-200", "answered",
			"liveness-only, owner can revert", "81dfad6492"),
		// not flagged: low-risk row (tier 2, gap 1) with the same reason
		probePriorityVal("Q-201", "answered", "no profit here", "0000000001"),
		// not flagged: high-risk row closed with a clean reason
		probePriorityVal("Q-202", "answered",
			"checked it thoroughly by hand", "81dfad6492"),
		// not flagged: high-risk row still open
		probePriorityVal("Q-203", "open", "", "81dfad6492"),
		// not flagged: a non-probe priority closed with dismissal words
		validation.VObj(kv("id", validation.VStr("Q-204")), kv("status", validation.VStr("answered")),
			kv("closed_reason", validation.VStr("no economic impact"))),
	)))
	lowSurface := deepCopy(t, *surface)
	lowRow := dgLowRow(t)
	rows := validation.VArr()
	for _, r := range listOf(*surface, "rows") {
		rows.A = append(rows.A, r)
	}
	rows.A = append(rows.A, lowRow)
	lowSurface.O = setOrAppend(lowSurface.O, "rows", rows)
	withProbes(t, probeEnv{surface: &lowSurface, index: nil})

	flags, err := DispositionReview(camp, plan)
	if err != nil {
		t.Fatalf("DispositionReview: %v", err)
	}
	if len(flags) != 1 {
		t.Fatalf("flags = %d, want exactly 1 (Q-200): %+v", len(flags), flags)
	}
	f := flags[0]
	if f.Priority != "Q-200" || f.RowID != "81dfad6492" || f.Tier != 0 ||
		f.Gap != 4 {
		t.Errorf("flag = %+v", f)
	}
	if f.Reason != "liveness-only, owner can revert" {
		t.Errorf("flag reason = %q", f.Reason)
	}
	if len(f.Phrases) != 2 || f.Phrases[0] != "liveness-only" ||
		f.Phrases[1] != "owner can revert" {
		t.Errorf("flag phrases = %v", f.Phrases)
	}
}

// TestDispositionReviewNoSurface pins the absence arm: with no probe surface
// (the default PB) nothing is flagged and no error is raised — the v1 scan
// is a no-op, never a failure.
func TestDispositionReviewNoSurface(t *testing.T) {
	camp := newCampaign(t, "dg-nosurface")
	plan := validation.VObj(kv("priorities", validation.VArr(
		probePriorityVal("Q-300", "answered", "liveness-only", "81dfad6492"),
	)))
	flags, err := DispositionReview(camp, plan)
	if err != nil {
		t.Fatalf("DispositionReview without surface: %v", err)
	}
	if len(flags) != 0 {
		t.Fatalf("flags = %+v, want none without a surface", flags)
	}
}
