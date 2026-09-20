package planner

// disposition_test.go — IMPROVEMENTS B4: the disposition linter. Pins the
// dismissal vocabulary, the high-risk row rule, the v2 gate (rejection,
// refutation backing, override + event), and the v1 review scan.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
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
		if validation.ObjStr(r, "row_id") == "81dfad6492" {
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
	row.O = validation.SetOrAppend(row.O, "row_id", validation.VStr("0000000001"))
	row.O = validation.SetOrAppend(row.O, "tier", validation.VInt(2))
	row.O = validation.SetOrAppend(row.O, "assertion_gap", validation.VInt(1))
	return row
}

// dgSurfaceOffAxis is the fixture surface with rowID's axis re-tuned away
// from enforcement-timing (morph §6.1/§7.1). The structural trigger answers
// BEFORE the lexical FIX-5 triggers, so a test that pins a lexical trigger
// has to take its row off the axis — the same move dgLowRow makes for
// tier/gap. Every other row field is kept, so the anchor path still resolves.
func dgSurfaceOffAxis(t *testing.T, surface *validation.Value, rowID,
	axis string) *validation.Value {
	t.Helper()
	out := deepCopy(t, *surface)
	found := false
	for i, r := range listOf(out, "rows") {
		if validation.ObjStr(r, "row_id") != rowID {
			continue
		}
		found = true
		r.O = validation.SetOrAppend(r.O, "axis", validation.VStr(axis))
		listOf(out, "rows")[i] = r
	}
	if !found {
		t.Fatalf("fixture row %s is gone", rowID)
	}
	return &out
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
		v.O = validation.SetOrAppend(v.O, "closed_reason", validation.VStr(reason))
	}
	v.O = validation.SetOrAppend(v.O, "probe", validation.VObj(
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
	// morph §6.1/§7.1: every fixture row sits on the enforcement-timing
	// axis, so the deferred-consequence gate (which runs BEFORE the
	// dismissal gate) now demands the interim pricing on every high-risk
	// closure. The cases below price it, so each one still reaches and
	// exercises the dismissal rule it is about.
	interim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"

	// (a) no ref, no override: rejected, with the phrases + guidance
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			Interim: &interim})
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
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			Ref: &refFile, Interim: &interim})
	if err == nil || !strings.Contains(err.Error(), "dismissal vocabulary") {
		t.Fatalf("file#L ref must not back a dismissal, err = %v", err)
	}

	// (c) an EXEC id with no record on disk: rejected as a FABRICATED
	// citation — v3 answers this before the anchor rule, because "no such
	// exec record" is more useful than "that is not the anchor it claims"
	refGhost := "EXEC-0000000000"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refGhost})
	if err == nil || !strings.Contains(err.Error(), "which does not exist") {
		t.Fatalf("ghost EXEC ref must be rejected as fabricated, err = %v", err)
	}

	// (d) a real exec record on disk: the refutation backs the closure.
	// R3-5(ii): the record names the finding the exec ran for — an
	// ANONYMOUS exec no longer escapes the anchor rule (TestExecEscapeMust-
	// NameItsFinding pins that refusal).
	refExec := "EXEC-abcdef1234"
	exDir := filepath.Join(camp.ExecsDir, refExec)
	if err := os.MkdirAll(exDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exDir, "exec_record.json"),
		[]byte(`{"exec_id":"`+refExec+
			`","finding_id":"F-000000000000"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refExec,
			Interim: &interim})
	if err != nil {
		t.Fatalf("exec-backed dismissal must pass: %v", err)
	}
	p := probePriority(t, plan, "Q-005")
	if got := validation.ObjStr(p, "closed_ref"); got != refExec {
		t.Errorf("closed_ref = %q, want the refutation %q", got, refExec)
	}
	// the anchor record keeps its own citation of the field
	if got := validation.ObjStr(validation.ObjAt(validation.ObjAt(p, "probe"), "anchor"), "ref"); got != refFile {
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
	// Q-006 is a different surface row (dropMessage / auditDrop), so its
	// pricing has to cite ITS symbols, not Q-005's.
	interimNA := "until auditDrop asserts dropped:msg, dropMessage consumes " +
		"an unverified root"
	plan, err = MarkAnswered(camp, plan, "Q-006", "not-applicable",
		AnsweredOpts{Reason: &reasonNA, Anchor: strPtr("consumer"), Ref: &refInv,
			Interim: &interimNA})
	if err != nil {
		t.Fatalf("invariant-backed dismissal must pass: %v", err)
	}

	// (g) v3: clean prose that names nothing from the row is refused too. The
	// vocabulary table (v2) catches the historical wording; this catches its
	// substitutes — a reason that could have been written without opening the
	// file is not a disposition, it is a hope.
	vague := "the whole thing looked fine when I traced it"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &vague, Anchor: strPtr("consumer"),
			Interim: &interim})
	if err == nil || !strings.Contains(err.Error(), "names nothing from the "+
		"row's own surface entry") {
		t.Fatalf("uncited prose on a tier-0 row must be rejected, err = %v", err)
	}
	for _, want := range []string{"commitBatch", "EXEC-", "--override-dismissal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("v3 rejection %q missing %q", err, want)
		}
	}

	// (h) the same closure with the row's own code named: accepted, because
	// the rule is satisfiable by writing the reason properly.
	cited := "commitBatch re-derives prev:state before consuming it"
	planCited, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &cited, Anchor: strPtr("consumer"),
			Interim: &interim})
	if err != nil {
		t.Fatalf("a cited reason must pass: %v", err)
	}
	if got := validation.ObjStr(probePriority(t, planCited, "Q-005"), "closed_reason"); got != cited {
		t.Errorf("closed_reason = %q", got)
	}

	// (f) an INV id not in the registry: rejected as fabricated by v3
	refGhostInv := "INV-9"
	_, err = MarkAnswered(camp, plan, "Q-007", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refGhostInv})
	if err == nil || !strings.Contains(err.Error(), "INV-9") ||
		!strings.Contains(err.Error(), "which does not exist") {
		t.Fatalf("ghost INV ref must be rejected as fabricated, err = %v", err)
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
	lowPlan.O = validation.SetOrAppend(lowPlan.O, "priorities", validation.VArr(
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
	if got := validation.ObjStr(p, "status"); got != "answered" {
		t.Fatalf("status = %q, want answered", got)
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found validation.Value
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			found = e
		}
	}
	if found.Kind == validation.Null {
		t.Fatal("no probe.dismissal_overridden event logged")
	}
	data := validation.ObjAt(found, "data")
	if got := validation.ObjStr(data, "row_id"); got != "81dfad6492" {
		t.Errorf("event row_id = %q", got)
	}
	if got := validation.ObjAt(data, "tier").I; got != 0 {
		t.Errorf("event tier = %d, want 0", got)
	}
	if got := validation.ObjAt(data, "assertion_gap").I; got != 4 {
		t.Errorf("event assertion_gap = %d, want 4", got)
	}
	if got := validation.ObjStr(data, "actor"); got != "operator" {
		t.Errorf("event actor = %q, want operator", got)
	}
	if got := validation.ObjStr(data, "override_reason"); got != why {
		t.Errorf("event override_reason = %q", got)
	}
	if got := validation.ObjStr(data, "closed_reason"); got != reason {
		t.Errorf("event closed_reason = %q", got)
	}
	phrases := listOf(data, "phrases")
	if len(phrases) != 2 || validation.ObjStr(phrases[0], "") != "" ||
		phrases[0].S != "not exploitable" || phrases[1].S != "never permanently" {
		t.Errorf("event phrases = %v, want [not exploitable never permanently]",
			phrases)
	}
}

// TestDispositionReview pins the v1 scan: only high-risk CLOSED probe rows
// with dismissal vocabulary are flagged, in plan order; low-risk rows,
// clean reasons, open rows, and non-probe rows are never flagged.
// TestDismissalOverrideNoticeIsSpecific: the notice must mean "an override was
// recorded", not "the flag was passed". A dismissal that clears the gate on a
// real refutation records no override, so it must not report one.
func TestDismissalOverrideNoticeIsSpecific(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dg-notice")

	// a registered invariant, so the gate's refutation branch really fires
	links := validation.VObj(kv("invariants", validation.VObj(kv("INV-1",
		validation.VObj(
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

	reason := "no economic impact: the invariant refutes the row"
	ref := "INV-1"
	// morph §6.1/§7.1: the fixture row sits on the enforcement-timing axis,
	// so the deferred-consequence gate (which runs BEFORE the dismissal
	// gate) demands the interim pricing on every high-risk closure; pricing
	// it here keeps this arm on the notice rule it is about.
	interim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	logged := false
	_, err := MarkAnswered(camp, deepCopy(t, maPlan(t, "plan_probe_rows.json")),
		"Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &ref,
			Interim: &interim, OverrideLogged: &logged})
	if err != nil {
		t.Fatalf("invariant-backed dismissal must pass: %v", err)
	}
	if logged {
		t.Error("OverrideLogged set without an override — the notice claims a " +
			"decision the operator never made")
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			t.Error("a refutation-backed dismissal logged a dismissal override")
		}
	}
}

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
	lowSurface.O = validation.SetOrAppend(lowSurface.O, "rows", rows)
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

// ---------------------------------------------------------------------------
// v3: the structural layer
// ---------------------------------------------------------------------------

// TestRowSymbolsReadTheRowsOwnEntry pins what counts as a citation: the row's
// contract, the function it is about, the asserter, the concept keys, the
// forward path and the siblings — in that order, deduplicated, and without the
// tokens that name no code.
func TestRowSymbolsReadTheRowsOwnEntry(t *testing.T) {
	surface, _ := maSurface(t)
	rows := listOf(*surface, "rows")
	row := validation.VNull()
	for _, r := range rows {
		if validation.ObjStr(r, "row_id") == "81dfad6492" {
			row = r
		}
	}
	if row.Kind == validation.Null {
		t.Fatal("fixture row 81dfad6492 is gone")
	}
	got := RowSymbols(row)
	want := []string{"Rollup", "commitBatch", "finalizeBatch", "batch:index",
		"prev:state", "prev:state:root", "state:root", "MockRollup"}
	if len(got) != len(want) {
		t.Fatalf("symbols = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("symbols[%d] = %q, want %q (%v)", i, got[i], want[i], got)
		}
	}

	// a custody verb is not a citation, and neither is a line number
	custodyRow := validation.VObj(
		kv("contract", validation.VStr("Vault")),
		kv("consumer", validation.VStr("withdraw")),
		kv("custody", validation.VStr("burns")),
		kv("base", validation.VStr("")),
		kv("forward", validation.VArr(validation.VStr("forwards"), validation.VStr(""))),
	)
	got = RowSymbols(custodyRow)
	if len(got) != 2 || got[0] != "Vault" || got[1] != "withdraw" {
		t.Fatalf("symbols = %v, want [Vault withdraw]", got)
	}
}

// TestARowWithNoSymbolsStaysClosable is the false-refusal guard: the rule
// exists to make a dismissal checkable, never to make a row unclosable. A row
// that names nothing falls back to the policy's own wording.
func TestARowWithNoSymbolsStaysClosable(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	stripped := deepCopy(t, *surface)
	found := false
	for i, r := range listOf(stripped, "rows") {
		if validation.ObjStr(r, "row_id") != "81dfad6492" {
			continue
		}
		found = true
		drop := map[string]bool{"contract": true, "consumer": true,
			"base": true, "asserter": true, "custody": true,
			"concept_keys": true, "forward": true, "siblings": true,
			"why": true}
		kept := []validation.KV{}
		for _, pair := range r.O {
			if !drop[pair.K] {
				kept = append(kept, pair)
			}
		}
		r.O = kept
		if got := RowSymbols(r); len(got) != 0 {
			t.Fatalf("stripped row still reports symbols %v", got)
		}
		listOf(stripped, "rows")[i] = r
	}
	if !found {
		t.Fatal("fixture row 81dfad6492 is gone")
	}
	withProbes(t, probeEnv{surface: &stripped, index: index})
	camp := newCampaign(t, "dg-nosym")
	vague := "the whole thing looked fine when I traced it"
	prov := validation.VObj(kv("row_id", validation.VStr("81dfad6492")))
	if err := checkDismissalGate(camp, "Q-005", "answered", prov, true,
		AnsweredOpts{Reason: &vague}); err != nil {
		t.Fatalf("a row that names nothing must stay closable: %v", err)
	}
}

// TestGhostCitationsAreRefused pins v3's converse duty and its blast radius: a
// well-formed id that resolves to nothing is refused at any tier, while a
// token that merely looks id-ish is prose, not a citation.
func TestGhostCitationsAreRefused(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dg-ghost")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	// the citation duty is not a policy about high-risk rows: the ghost scan
	// answers before the gate ever looks at the tier
	row := listOf(*surface, "rows")[0]
	pid := ""
	for _, p := range listOf(plan, "priorities") {
		if prov, ok := probeProvenance(p); ok &&
			validation.ObjStr(prov, "row_id") == validation.ObjStr(row, "row_id") {
			pid = validation.ObjStr(p, "id")
		}
	}
	if pid == "" {
		t.Fatal("fixture row has no priority")
	}
	for _, tc := range []struct{ name, reason, want string }{
		{"finding", "answered against F-000000000000 for completeness", "F-000000000000"},
		{"exec", "the EXEC-0123456789 run settles it", "EXEC-0123456789"},
		{"invariant", "INV-42 rules this out", "INV-42"},
	} {
		_, err := MarkAnswered(camp, deepCopy(t, plan), pid, "answered",
			AnsweredOpts{Reason: &tc.reason, Anchor: strPtr("consumer")})
		if err == nil || !strings.Contains(err.Error(), tc.want) ||
			!strings.Contains(err.Error(), "which does not exist") {
			t.Errorf("%s: err = %v, want a refusal naming %s", tc.name, err, tc.want)
		}
	}
	// prose that only looks like an id is left alone (and the reason still has
	// to cite the row, which it does). morph §6.1/§7.1: the enforcement-timing
	// row also owes the interim pricing, or the deferred gate — which runs
	// before the citation scan — answers instead of the rule under test.
	ok := "the F-1 code path and INV-x never converge inside commitBatch"
	ghostInterim := "until finalizeBatch asserts prev:state, commitBatch " +
		"consumes an unverified root"
	if _, err := MarkAnswered(camp, deepCopy(t, plan), pid, "answered",
		AnsweredOpts{Reason: &ok, Anchor: strPtr("consumer"),
			Interim: &ghostInterim}); err != nil {
		t.Fatalf("id-shaped prose must not be read as a citation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// B4 v3: the sentinel-form rule (Task 2)
// ---------------------------------------------------------------------------

// sentinelDispositionFixture is the surface + campaign the sentinel rule is
// exercised against: the file's recorded surface, with the one probe row's
// object extended by the Task-1 sentinel enrichment (own_form=sentinel,
// own_guard_text), and the recorded plan saved into a fresh campaign so the
// refusing path can be read back off disk. It returns the campaign, the
// surface in force, and the row id the plan's priority points at.
func sentinelDispositionFixture(t *testing.T) (*state.Campaign,
	*validation.Value, string) {
	t.Helper()
	surface, index := maSurface(t)
	const rowID = "81dfad6492"
	found := false
	for i, r := range listOf(*surface, "rows") {
		if validation.ObjStr(r, "row_id") != rowID {
			continue
		}
		found = true
		r.O = validation.SetOrAppend(r.O, "own_form",
			validation.VStr("sentinel"))
		r.O = validation.SetOrAppend(r.O, "own_guard_text",
			validation.VStr("root != bytes32(0)"))
		listOf(*surface, "rows")[i] = r
	}
	if !found {
		t.Fatalf("fixture row %s is gone", rowID)
	}
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dg-sentinel")
	if _, err := SavePlan(camp, deepCopy(t, maPlan(t,
		"plan_probe_rows.json"))); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	return camp, surface, rowID
}

// priorityIDForRow is the plan priority whose probe provenance cites rowID.
func priorityIDForRow(t *testing.T, plan validation.Value, rowID string) string {
	t.Helper()
	for _, p := range listOf(plan, "priorities") {
		if prov, ok := probeProvenance(p); ok &&
			validation.ObjStr(prov, "row_id") == rowID {
			return validation.ObjStr(p, "id")
		}
	}
	t.Fatalf("no priority cites probe row %s", rowID)
	return ""
}

// plannerMarkAnsweredForTest drives MarkAnswered the way the CLI does — the
// plan is read back from the campaign — and keeps the priority id in the
// return values so a test can inspect what landed.
func plannerMarkAnsweredForTest(t *testing.T, camp *state.Campaign, rowID,
	outcome string, opts *AnsweredOpts) (validation.Value, string, error) {
	t.Helper()
	plan, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	pid := priorityIDForRow(t, plan, rowID)
	updated, err := MarkAnswered(camp, plan, pid, outcome, *opts)
	return updated, pid, err
}

// storedPriority is the on-disk priority the row was dispositioned as: the
// record a refusal must leave byte-for-byte alone.
func storedPriority(t *testing.T, camp *state.Campaign,
	rowID string) validation.Value {
	t.Helper()
	plan, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatalf("reload plan: %v", err)
	}
	return probePriority(t, plan, priorityIDForRow(t, plan, rowID))
}

// TestDispositionLintSentinelRowDemandsPasses: a closing disposition of a
// sentinel-guarded row (own_form=sentinel from the surface) is refused
// without --passes, accepted with it, and the stored priority carries it.
func TestDispositionLintSentinelRowDemandsPasses(t *testing.T) {
	// Fixture: the disposition_test.go surface builder, with the one row's
	// object extended by own_form:"sentinel", own_guard_text:"root != bytes32(0)".
	camp, _, rowID := sentinelDispositionFixture(t)

	_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer")})
	if err == nil || !strings.Contains(err.Error(),
		"a closing disposition must name the value that passes its check") {
		t.Fatalf("err = %v, want the sentinel --passes refusal", err)
	}

	passes := "any non-zero root; its truth is asserted at finalizeBatch"
	// morph §6.1/§7.1: the enforcement-timing row owes the interim pricing
	// too; the sentinel rule under test runs first and is what this arm
	// exercises.
	sentInterim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	_, _, err = plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &passes,
			Interim: &sentInterim})
	if err != nil {
		t.Fatalf("with --passes: %v", err)
	}
	prio := storedPriority(t, camp, rowID)
	if validation.ObjStr(prio, "passes") != passes {
		t.Errorf("passes = %q", validation.ObjStr(prio, "passes"))
	}
}

// TestDispositionLintSentinelRowOverride: the family's one escape hatch still
// opens the sentinel rule — an explicit, logged override closes the row
// without a --passes value (and records none).
func TestDispositionLintSentinelRowOverride(t *testing.T) {
	camp, _, rowID := sentinelDispositionFixture(t)
	why := "the owner confirmed the intended behavior in the spec"
	_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), OverrideDismissal: true,
			OverrideReason: &why})
	if err != nil {
		t.Fatalf("an explicit override must pass the sentinel rule: %v", err)
	}
	prio := storedPriority(t, camp, rowID)
	if got := validation.ObjStr(prio, "status"); got != "answered" {
		t.Errorf("status = %q, want answered", got)
	}
	if got := validation.ObjStr(prio, "passes"); got != "" {
		t.Errorf("passes = %q, want none (the override is the record)", got)
	}
}

// lowSentinelFixture is the sentinel fixture with the row re-tuned to
// tier 2 / gap 1 (not high-risk): the sentinel rule's override arm is
// exercised on its own, without the dismissal gate — which records the same
// event on a high-risk row — also firing.
func lowSentinelFixture(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	surface, index := maSurface(t)
	found := false
	for i, r := range listOf(*surface, "rows") {
		if validation.ObjStr(r, "row_id") != "81dfad6492" {
			continue
		}
		found = true
		r.O = validation.SetOrAppend(r.O, "tier", validation.VInt(2))
		r.O = validation.SetOrAppend(r.O, "assertion_gap", validation.VInt(1))
		r.O = validation.SetOrAppend(r.O, "own_form",
			validation.VStr("sentinel"))
		r.O = validation.SetOrAppend(r.O, "own_guard_text",
			validation.VStr("root != bytes32(0)"))
		listOf(*surface, "rows")[i] = r
	}
	if !found {
		t.Fatal("fixture row 81dfad6492 is gone")
	}
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dg-sentinel-low")
	if _, err := SavePlan(camp, deepCopy(t, maPlan(t,
		"plan_probe_rows.json"))); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	return camp, "81dfad6492"
}

// TestDispositionLintSentinelRowOverrideNeedsReason pins FIX-2: the sentinel
// rule's escape hatch is the dismissal gate's logged override, never a bare
// flag. A bare --override-dismissal — and one with a blank reason — is
// refused with the row's risk shape in the head, leaving the priority
// untouched and unpassed.
func TestDispositionLintSentinelRowOverrideNeedsReason(t *testing.T) {
	camp, rowID := lowSentinelFixture(t)

	_, pid, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), OverrideDismissal: true})
	if err == nil || !strings.Contains(err.Error(),
		"--override-dismissal needs --override-reason") {
		t.Fatalf("bare override must be refused, err = %v", err)
	}
	// the refusal mirrors the dismissal gate's wording: the head carries the
	// priority, the probe row and its risk shape
	if want := "priority " + pid + " (probe row " + rowID +
		", tier 2, assertion_gap 1): --override-dismissal needs " +
		"--override-reason"; !strings.Contains(err.Error(), want) {
		t.Errorf("refusal = %q, want the head %q", err, want)
	}
	// the refusal is a decision that did not happen
	prio := storedPriority(t, camp, rowID)
	if got := validation.ObjStr(prio, "status"); got != "open" {
		t.Fatalf("refused closure changed the status to %q", got)
	}
	if validation.ObjAt(prio, "passes").Kind != validation.Null {
		t.Fatalf("refused closure recorded passes = %q",
			validation.ObjStr(prio, "passes"))
	}

	// negative control: a whitespace-only reason is not a justification
	blank := "   "
	_, _, err = plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), OverrideDismissal: true,
			OverrideReason: &blank})
	if err == nil || !strings.Contains(err.Error(),
		"--override-dismissal needs --override-reason") {
		t.Fatalf("blank override reason must be refused, err = %v", err)
	}

	// FIX-8: a bare override on the non-sentinel rows of the same surface is
	// refused too — the override answers a refusal, it is not a formality,
	// and an unreasoned override on any row is no longer swallowed silently
	// (it used to exit 0 with no event and no notice).
	_, _, err = plannerMarkAnsweredForTest(t, camp, rowID, "deprioritized",
		&AnsweredOpts{Anchor: strPtr("consumer"), OverrideDismissal: true})
	if err == nil || !strings.Contains(err.Error(),
		"--override-dismissal needs --override-reason") {
		t.Fatalf("bare override on a non-sentinel row must be refused, "+
			"err = %v", err)
	}
}

// TestDispositionLintSentinelRowOverrideIsLogged pins the recorded half of
// FIX-2: an override with a reason closes the row and logs exactly one
// probe.dismissal_overridden with the same provenance the high-risk branch
// records (row, tier, gap, actor, phrases, both reasons) — and the notice
// out-param is set, so the CLI can announce it.
func TestDispositionLintSentinelRowOverrideIsLogged(t *testing.T) {
	camp, rowID := lowSentinelFixture(t)
	why := "the owner confirmed the intended behavior in the spec"
	reason := "no profit here"
	logged := false
	_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true, OverrideReason: &why,
			Actor: "operator", OverrideLogged: &logged})
	if err != nil {
		t.Fatalf("override with reason must pass: %v", err)
	}
	if !logged {
		t.Error("OverrideLogged not set — the override went unannounced")
	}
	prio := storedPriority(t, camp, rowID)
	if got := validation.ObjStr(prio, "status"); got != "answered" {
		t.Fatalf("status = %q, want answered", got)
	}
	if validation.ObjAt(prio, "passes").Kind != validation.Null {
		t.Fatalf("passes = %q, want none (the override is the record)",
			validation.ObjStr(prio, "passes"))
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found []validation.Value
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want exactly 1",
			len(found))
	}
	data := validation.ObjAt(found[0], "data")
	if got := validation.ObjStr(data, "row_id"); got != rowID {
		t.Errorf("event row_id = %q, want %q", got, rowID)
	}
	if got := validation.ObjAt(data, "tier").I; got != 2 {
		t.Errorf("event tier = %d, want 2", got)
	}
	if got := validation.ObjAt(data, "assertion_gap").I; got != 1 {
		t.Errorf("event assertion_gap = %d, want 1", got)
	}
	if got := validation.ObjStr(data, "actor"); got != "operator" {
		t.Errorf("event actor = %q, want operator", got)
	}
	if got := validation.ObjStr(data, "override_reason"); got != why {
		t.Errorf("event override_reason = %q", got)
	}
	if got := validation.ObjStr(data, "closed_reason"); got != reason {
		t.Errorf("event closed_reason = %q", got)
	}
	if phrases := listOf(data, "phrases"); len(phrases) != 1 ||
		phrases[0].S != "no profit" {
		t.Errorf("event phrases = %v, want [no profit]", phrases)
	}
}

// TestDispositionLintSentinelOverrideHighRiskIsOneEvent pins the one-event
// law across the two gates: a HIGH-risk sentinel row overridden with a
// dismissal-vocabulary reason would be recorded by BOTH the sentinel arm and
// the dismissal gate (which runs after it with the same opts) — the closure
// must carry exactly one probe.dismissal_overridden, in the high-risk
// branch's shape.
func TestDispositionLintSentinelOverrideHighRiskIsOneEvent(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	camp, _, rowID := sentinelDispositionFixture(t)
	reason := "liveness-only, the owner can revert"
	why := "the owner confirmed the intended behavior in the spec"
	logged := false
	_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true, OverrideReason: &why,
			Actor: "operator", OverrideLogged: &logged})
	if err != nil {
		t.Fatalf("override with reason must pass: %v", err)
	}
	if !logged {
		t.Error("OverrideLogged not set — the override went unannounced")
	}
	prio := storedPriority(t, camp, rowID)
	if got := validation.ObjStr(prio, "status"); got != "answered" {
		t.Fatalf("status = %q, want answered", got)
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found []validation.Value
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want exactly 1",
			len(found))
	}
	data := validation.ObjAt(found[0], "data")
	if got := validation.ObjStr(data, "row_id"); got != rowID {
		t.Errorf("event row_id = %q", got)
	}
	if got := validation.ObjAt(data, "tier").I; got != 0 {
		t.Errorf("event tier = %d, want 0", got)
	}
	if got := validation.ObjAt(data, "assertion_gap").I; got != 4 {
		t.Errorf("event assertion_gap = %d, want 4", got)
	}
	phrases := listOf(data, "phrases")
	if len(phrases) != 2 || phrases[0].S != "liveness-only" ||
		phrases[1].S != "owner can revert" {
		t.Errorf("event phrases = %v, want [liveness-only owner can revert]",
			phrases)
	}
	if got := validation.ObjStr(data, "override_reason"); got != why {
		t.Errorf("event override_reason = %q", got)
	}
}

// TestDispositionLintSentinelOverrideDryRunRecordsNothing pins the pre-flight
// half of FIX-2: the batch pre-flight validates the sentinel override but
// records NOTHING, so a batch refused on a later row leaves the plan
// byte-identical and zero events behind.
func TestDispositionLintSentinelOverrideDryRunRecordsNothing(t *testing.T) {
	camp, rowID := lowSentinelFixture(t)
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	before := batchPlanFiles(t, camp, plan)
	pid := priorityIDForRow(t, plan, rowID)
	anchor := "consumer"
	_, err := MarkAnsweredBatch(camp, plan, []AnsweredRow{
		{PriorityID: pid, Outcome: "answered",
			Opts: AnsweredOpts{
				Reason:            strPtr("no profit here"),
				Anchor:            &anchor,
				OverrideDismissal: true,
				OverrideReason: strPtr("the owner confirmed the " +
					"intended behavior in the spec"),
			}},
		{PriorityID: "Q-999", Outcome: "answered", Opts: AnsweredOpts{}},
	}, "batch review of the queue")
	if err == nil {
		t.Fatal("a batch with an unknown trailing row must be refused")
	}
	if got := err.Error(); !strings.HasPrefix(got,
		"answered: row 2 (Q-999):") {
		t.Fatalf("refusal must name the unknown row: %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Fatal("refused batch mutated the plan file")
	}
	if evts := batchEventsOfType(t, camp,
		"probe.dismissal_overridden"); len(evts) != 0 {
		t.Fatalf("pre-flight must not record the override: %d events",
			len(evts))
	}
	if evts := batchEventsOfType(t, camp,
		"plan.priority_status"); len(evts) != 0 {
		t.Fatalf("refused batch logged %d plan.priority_status events",
			len(evts))
	}
}

// ---------------------------------------------------------------------------
// FIX-5: the deferred-consequence gate + the reverse sweep
// ---------------------------------------------------------------------------

// TestDeferredHitsTable pins the sweep vocabulary: every token is detected
// whole-word and case-insensitively, a clean reason gets no hits, multiple
// hits come back in table order, and a token inside a larger word is prose,
// not the tell.
func TestDeferredHitsTable(t *testing.T) {
	if len(DeferredConsequenceTokens) != 9 {
		t.Fatalf("vocabulary size = %d, want 9",
			len(DeferredConsequenceTokens))
	}
	for _, tok := range DeferredConsequenceTokens {
		hits := DeferredHits("the row stays " + strings.ToUpper(tok) + " here")
		if len(hits) != 1 || hits[0] != tok {
			t.Errorf("token %q: hits = %v, want [%s]", tok, hits, tok)
		}
	}
	if hits := DeferredHits("the check runs at finalizeBatch as designed"); len(hits) != 0 {
		t.Errorf("clean reason: hits = %v, want none", hits)
	}
	// whole-word: "strand" does not hide inside "stranded", and neither
	// token hides inside "restranding"
	if hits := DeferredHits("funds stranded in the escrow"); len(hits) != 1 ||
		hits[0] != "stranded" {
		t.Errorf("stranded: hits = %v", hits)
	}
	if hits := DeferredHits("unfinalizablestate"); len(hits) != 0 {
		t.Errorf("glued token: hits = %v, want none", hits)
	}
	multi := DeferredHits("the pool is FROZEN and the queue is REVERT-FOREVER")
	want := []string{"frozen", "revert-forever"}
	if len(multi) != len(want) {
		t.Fatalf("multi hits = %v, want %v", multi, want)
	}
	for i := range want {
		if multi[i] != want[i] {
			t.Errorf("multi hit %d = %q, want %q", i, multi[i], want[i])
		}
	}
}

// dcSeed writes a filed finding so a --finding ref resolves.
func dcSeedFinding(t *testing.T, camp *state.Campaign, id string) {
	t.Helper()
	if err := os.MkdirAll(camp.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(camp.FindingsDir, id+".json"),
		[]byte(`{"finding_id":"`+id+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDeferredConsequenceGateMatrix pins the FIX-5 gate: a tier-0 row closed
// on the asserter anchor must price the interim window — a filed finding or
// a consequence statement citing the row's own surface entry — while
// low-risk rows and blocked outcomes never trip it. Morph §6.1/§7.1 widens
// the trigger structurally: every fixture row sits on the enforcement-timing
// axis, so ANY anchor on a high-risk one now owes the pricing too (case (i)).
func TestDeferredConsequenceGateMatrix(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dc-matrix")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	reason := "commitBatch consumes prev:state before the assertion runs"

	// (a) no interim, no finding: refused, with the shape taught
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter")})
	if err == nil {
		t.Fatal("an unpriced asserter-anchor closure must be rejected")
	}
	for _, want := range []string{"anchors on asserter", "finalizeBatch",
		"commitBatch", "--finding F-<id>", "--interim STATEMENT",
		"--override-dismissal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection %q missing %q", err, want)
		}
	}

	// (b) accepted with a consequence statement that cites the row's own
	// entry — and the statement is recorded on the priority
	interim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	planInterim, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005",
		"answered", AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter"),
			Interim: &interim})
	if err != nil {
		t.Fatalf("a symbol-citing --interim must pass: %v", err)
	}
	if got := validation.ObjStr(probePriority(t, planInterim, "Q-005"), "interim"); got != interim {
		t.Errorf("interim = %q, want %q", got, interim)
	}

	// (c) accepted with a filed finding id — recorded as interim_finding
	dcSeedFinding(t, camp, "F-1a2b3c4d5e6f")
	ref := "F-1a2b3c4d5e6f"
	planFinding, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005",
		"answered", AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter"),
			Finding: &ref})
	if err != nil {
		t.Fatalf("a filed --finding must pass: %v", err)
	}
	if got := validation.ObjStr(probePriority(t, planFinding, "Q-005"),
		"interim_finding"); got != ref {
		t.Errorf("interim_finding = %q, want %q", got, ref)
	}

	// (d) a ghost finding id is refused as fabricated
	ghost := "F-000000000000"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter"),
			Finding: &ghost})
	if err == nil || !strings.Contains(err.Error(), "F-000000000000") ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("ghost --finding must be refused, err = %v", err)
	}

	// (e) a value that is not a finding id at all is refused as malformed
	malformed := "the big one"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter"),
			Finding: &malformed})
	if err == nil || !strings.Contains(err.Error(), "is not a finding id") {
		t.Fatalf("malformed --finding must be refused, err = %v", err)
	}

	// (f) prose that names nothing from the row is refused — the v3 citation
	// muscle, applied to the interim statement
	vague := "we looked at it carefully and it holds"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter"),
			Interim: &vague})
	if err == nil || !strings.Contains(err.Error(), "names nothing from the "+
		"row's own surface entry") {
		t.Fatalf("uncited --interim must be refused, err = %v", err)
	}

	// (g) the same closure on a LOW-risk row (tier 2, gap 1) passes without
	// any pricing — the gate only polices high-risk rows
	lowRow := dgLowRow(t)
	lowSurface := validation.VObj(kv("rows", validation.VArr(lowRow)))
	withProbes(t, probeEnv{surface: &lowSurface, index: index})
	lowCamp := newCampaign(t, "dc-low")
	lowPlan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	lowPlan.O = validation.SetOrAppend(lowPlan.O, "priorities", validation.VArr(
		append(listOf(lowPlan, "priorities"),
			probePriorityVal("Q-100", "open", "", "0000000001"))...))
	if _, err := MarkAnswered(lowCamp, lowPlan, "Q-100", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter")}); err != nil {
		t.Fatalf("low-risk asserter closure must pass without pricing: %v", err)
	}

	// (h) blocked is not a disposition: a tier-0 row closed as blocked on
	// the asserter anchor never trips the gate
	surface2, index2 := maSurface(t)
	withProbes(t, probeEnv{surface: surface2, index: index2})
	blockCamp := newCampaign(t, "dc-blocked")
	if _, err := MarkAnswered(blockCamp, deepCopy(t, maPlan(t,
		"plan_probe_rows.json")), "Q-005", "blocked",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter")}); err != nil {
		t.Fatalf("blocked is not a disposition, err = %v", err)
	}

	// (i) morph §6.1/§7.1: a non-asserter anchor on the same tier-0 row is no
	// longer unaffected — the row sits on the enforcement-timing axis, so the
	// STRUCTURAL trigger refuses the closure whatever the anchor, and its
	// refusal names the axis, never the asserter anchor the closure did not
	// use. Pricing the window is what lands the consumer-anchor closure now.
	surface3, index3 := maSurface(t)
	withProbes(t, probeEnv{surface: surface3, index: index3})
	consumerCamp := newCampaign(t, "dc-consumer")
	_, err = MarkAnswered(consumerCamp, deepCopy(t, maPlan(t,
		"plan_probe_rows.json")), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer")})
	if err == nil || !strings.Contains(err.Error(), "enforcement-timing") ||
		strings.Contains(err.Error(), "anchors on asserter") {
		t.Fatalf("a consumer anchor on the axis must trip the structural "+
			"trigger, err = %v", err)
	}
	consumerInterim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	if _, err := MarkAnswered(consumerCamp, deepCopy(t, maPlan(t,
		"plan_probe_rows.json")), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			Interim: &consumerInterim}); err != nil {
		t.Fatalf("a priced consumer-anchor closure must pass: %v", err)
	}
}

// TestDeferredConsequenceGateOverride pins the override arm: a bare
// --override-dismissal is refused, an override with a reason closes the row,
// and the closure carries exactly one probe.dismissal_overridden — even when
// the reason ALSO uses dismissal vocabulary (the deferred arm defers to the
// dismissal gate, which runs after it with the same opts).
func TestDeferredConsequenceGateOverride(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dc-override")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	reason := "commitBatch consumes prev:state; it stays unfinalizable"

	// bare override: refused before any state change
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter"),
			OverrideDismissal: true})
	if err == nil || !strings.Contains(err.Error(),
		"--override-dismissal needs --override-reason") {
		t.Fatalf("override without reason must be refused, err = %v", err)
	}
	p := probePriority(t, deepCopy(t, plan), "Q-005")
	if got := validation.ObjStr(p, "status"); got != "open" {
		t.Fatalf("refusal mutated the fixture plan status to %q", got)
	}

	// override with a reason: closes + logs exactly one audit event, even
	// though the reason carries BOTH the deferred tell and dismissal
	// vocabulary
	why := "the operator accepts the interim window in writing for this run"
	logged := false
	planOver, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("asserter"),
			OverrideDismissal: true, OverrideReason: &why, Actor: "operator",
			OverrideLogged: &logged})
	if err != nil {
		t.Fatalf("override with reason must pass: %v", err)
	}
	if !logged {
		t.Error("OverrideLogged not set — the override went unannounced")
	}
	if got := validation.ObjStr(probePriority(t, planOver, "Q-005"), "status"); got != "answered" {
		t.Errorf("status = %q, want answered", got)
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var found []validation.Value
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want exactly 1",
			len(found))
	}
	data := validation.ObjAt(found[0], "data")
	if got := validation.ObjStr(data, "row_id"); got != "81dfad6492" {
		t.Errorf("event row_id = %q", got)
	}
	if got := validation.ObjStr(data, "actor"); got != "operator" {
		t.Errorf("event actor = %q, want operator", got)
	}
	if got := validation.ObjStr(data, "override_reason"); got != why {
		t.Errorf("event override_reason = %q", got)
	}
}

// TestDeferredConsequenceOverrideWithoutReasonIsOneEvent pins the
// library-caller dedupe: with no closure reason the dismissal gate is a
// no-op, so the deferred arm records the override itself — and stays silent
// on a sentinel-form row, where the sentinel arm (which runs first) has
// already recorded it. One closure, one event, either way.
func TestDeferredConsequenceOverrideWithoutReasonIsOneEvent(t *testing.T) {
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dc-override-noreason")
	why := "the operator accepts the interim window in writing for this run"

	// non-sentinel row: the deferred arm records the event
	logged := false
	if _, err := MarkAnswered(camp, deepCopy(t, maPlan(t,
		"plan_probe_rows.json")), "Q-005", "answered",
		AnsweredOpts{Anchor: strPtr("asserter"), OverrideDismissal: true,
			OverrideReason: &why, Actor: "operator",
			OverrideLogged: &logged}); err != nil {
		t.Fatalf("override without a closure reason must pass: %v", err)
	}
	if !logged {
		t.Error("OverrideLogged not set — the override went unannounced")
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var logged1 []validation.Value
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			logged1 = append(logged1, e)
		}
	}
	if len(logged1) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want exactly 1",
			len(logged1))
	}

	// sentinel-form row: the sentinel arm already recorded it — the deferred
	// arm must not double-log
	sentSurface := deepCopy(t, *surface)
	for i, r := range listOf(sentSurface, "rows") {
		if validation.ObjStr(r, "row_id") != "81dfad6492" {
			continue
		}
		r.O = validation.SetOrAppend(r.O, "own_form",
			validation.VStr("sentinel"))
		r.O = validation.SetOrAppend(r.O, "own_guard_text",
			validation.VStr("root != bytes32(0)"))
		listOf(sentSurface, "rows")[i] = r
	}
	withProbes(t, probeEnv{surface: &sentSurface, index: index})
	sentCamp := newCampaign(t, "dc-override-sentinel")
	if _, err := MarkAnswered(sentCamp, deepCopy(t, maPlan(t,
		"plan_probe_rows.json")), "Q-005", "answered",
		AnsweredOpts{Anchor: strPtr("asserter"), OverrideDismissal: true,
			OverrideReason: &why, Actor: "operator"}); err != nil {
		t.Fatalf("sentinel+deferred override must pass: %v", err)
	}
	evts, err = sentCamp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var logged2 []validation.Value
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			logged2 = append(logged2, e)
		}
	}
	if len(logged2) != 1 {
		t.Fatalf("sentinel+deferred override events = %d, want exactly 1",
			len(logged2))
	}
}

// TestDeferredConsequenceDryRunRecordsNothing pins the pre-flight half: the
// batch pre-flight validates the deferred-consequence pricing but records
// NOTHING, so a batch refused on a later row leaves the plan byte-identical
// and zero events behind.
func TestDeferredConsequenceDryRunRecordsNothing(t *testing.T) {
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dc-dry")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	before := batchPlanFiles(t, camp, plan)
	pid := "Q-005"
	interim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	_, err := MarkAnsweredBatch(camp, plan, []AnsweredRow{
		{PriorityID: pid, Outcome: "answered",
			Opts: AnsweredOpts{
				Reason:  strPtr("commitBatch consumes prev:state"),
				Anchor:  strPtr("asserter"),
				Interim: &interim,
			}},
		{PriorityID: "Q-999", Outcome: "answered", Opts: AnsweredOpts{}},
	}, "batch review of the queue")
	if err == nil {
		t.Fatal("a batch with an unknown trailing row must be refused")
	}
	if got := err.Error(); !strings.HasPrefix(got,
		"answered: row 2 (Q-999):") {
		t.Fatalf("refusal must name the unknown row: %q", got)
	}
	raw, err := os.ReadFile(filepath.Join(camp.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Fatal("refused batch mutated the plan file")
	}
	if evts := batchEventsOfType(t, camp,
		"plan.priority_status"); len(evts) != 0 {
		t.Fatalf("refused batch logged %d plan.priority_status events",
			len(evts))
	}
}

// TestDeferredConsequenceReview pins the reverse sweep: only high-risk
// CLOSED probe rows whose reason uses the failure-consequence vocabulary and
// that record no interim pricing are flagged, in plan order; low-risk rows,
// clean reasons, open rows, non-probe rows and already-priced closures are
// never flagged.
func TestDeferredConsequenceReview(t *testing.T) {
	surface, _ := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: nil})
	camp := newCampaign(t, "dc-review")
	tell := "the row stays unfinalizable until the asserter runs"
	plan := validation.VObj(kv("priorities", validation.VArr(
		// flagged: tier-0/gap-4 row closed with the tell
		probePriorityVal("Q-200", "answered", tell, "81dfad6492"),
		// not flagged: low-risk row (tier 2, gap 1) with the same tell
		probePriorityVal("Q-201", "answered", tell, "0000000001"),
		// not flagged: high-risk row closed with a clean reason
		probePriorityVal("Q-202", "answered",
			"commitBatch re-derives the root itself", "81dfad6492"),
		// not flagged: high-risk row still open
		probePriorityVal("Q-203", "open", "", "81dfad6492"),
		// not flagged: a non-probe priority closed with the tell
		validation.VObj(kv("id", validation.VStr("Q-204")),
			kv("status", validation.VStr("answered")),
			kv("closed_reason", validation.VStr(tell))),
		// not flagged: already priced — the interim statement is recorded
		func() validation.Value {
			p := probePriorityVal("Q-205", "answered", tell, "81dfad6492")
			p.O = validation.SetOrAppend(p.O, "interim",
				validation.VStr("commitBatch holds the gap open"))
			return p
		}(),
	)))
	lowSurface := deepCopy(t, *surface)
	lowRow := dgLowRow(t)
	rows := validation.VArr()
	for _, r := range listOf(*surface, "rows") {
		rows.A = append(rows.A, r)
	}
	rows.A = append(rows.A, lowRow)
	lowSurface.O = validation.SetOrAppend(lowSurface.O, "rows", rows)
	withProbes(t, probeEnv{surface: &lowSurface, index: nil})

	flags, _, err := DeferredConsequenceReview(camp, plan)
	if err != nil {
		t.Fatalf("DeferredConsequenceReview: %v", err)
	}
	if len(flags) != 1 {
		t.Fatalf("flags = %d, want exactly 1 (Q-200): %+v", len(flags), flags)
	}
	f := flags[0]
	if f.Priority != "Q-200" || f.RowID != "81dfad6492" || f.Tier != 0 ||
		f.Gap != 4 {
		t.Errorf("flag = %+v", f)
	}
	if f.Reason != tell {
		t.Errorf("flag reason = %q", f.Reason)
	}
	if len(f.Tokens) != 1 || f.Tokens[0] != "unfinalizable" {
		t.Errorf("flag tokens = %v", f.Tokens)
	}
	// the sweep reports; it does not mutate — the plan value is unchanged
	if got := validation.ObjStr(validation.ObjAt(plan, "priorities").A[0], "closed_reason"); got != tell {
		t.Errorf("sweep mutated the plan: closed_reason = %q", got)
	}
}

// TestDeferredConsequenceReviewNoSurface pins the absence arm: with no probe
// surface nothing is flagged and no error is raised — the sweep is a no-op,
// never a failure. FIX-3: the tell-bearing closure is still NAMED, in the
// skipped list.
func TestDeferredConsequenceReviewNoSurface(t *testing.T) {
	camp := newCampaign(t, "dc-nosurface")
	plan := validation.VObj(kv("priorities", validation.VArr(
		probePriorityVal("Q-300", "answered",
			"unfinalizable until proven", "81dfad6492"),
	)))
	flags, skipped, err := DeferredConsequenceReview(camp, plan)
	if err != nil {
		t.Fatalf("DeferredConsequenceReview without surface: %v", err)
	}
	if len(flags) != 0 {
		t.Fatalf("flags = %+v, want none without a surface", flags)
	}
	if len(skipped) != 1 || skipped[0] != "Q-300 (probe row 81dfad6492)" {
		t.Fatalf("skipped = %+v, want the unrankable closure named", skipped)
	}
}

// TestDeferredConsequenceVocabularyTrigger pins FIX-1: the failure-consequence
// vocabulary is a trigger on its own — a high-risk row closed through ANY
// anchor on a reason that describes what happens when the row's deferred
// check never runs is refused until the window is priced, exactly as the
// asserter anchor's own concession demands. The priced exits and the logged
// override stay open, and neither the clean reason nor the low-risk row is
// affected.
func TestDeferredConsequenceVocabularyTrigger(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	// morph §6.1/§7.1: this test pins the LEXICAL FIX-1 trigger (the
	// failure-consequence vocabulary). The fixture row's own axis is
	// enforcement-timing, where the structural trigger answers first, so the
	// row is taken off the axis to keep this arm on the gate it is about.
	withProbes(t, probeEnv{surface: dgSurfaceOffAxis(t, surface, "81dfad6492",
		"guard-short-circuit"), index: index})
	camp := newCampaign(t, "dc-vocab")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	tell := "commitBatch consumes prev:state; it stays unfinalizable"

	// (a) consumer anchor + the tell: refused — the reason admits the
	// deferred window's cost, so the closure has to price it
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &tell, Anchor: strPtr("consumer")})
	if err == nil {
		t.Fatal("a consumer-anchor closure carrying the failure tell " +
			"must be refused")
	}
	for _, want := range []string{"failure-consequence vocabulary",
		"'unfinalizable'", "high-risk row", "--finding F-<id>",
		"--interim STATEMENT", "--override-dismissal"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal missing %q: %v", want, err)
		}
	}
	p := probePriority(t, deepCopy(t, plan), "Q-005")
	if got := validation.ObjStr(p, "status"); got != "open" {
		t.Fatalf("refusal mutated the fixture plan status to %q", got)
	}

	// (b) priced with a symbol-citing interim statement: passes, and the
	// statement is recorded on the priority
	interim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	planInterim, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005",
		"answered", AnsweredOpts{Reason: &tell, Anchor: strPtr("consumer"),
			Interim: &interim})
	if err != nil {
		t.Fatalf("a priced consumer-anchor closure must pass: %v", err)
	}
	if got := validation.ObjStr(probePriority(t, planInterim, "Q-005"), "interim"); got != interim {
		t.Errorf("interim = %q, want %q", got, interim)
	}

	// (c) priced with a filed finding: passes
	dcSeedFinding(t, camp, "F-1a2b3c4d5e6f")
	ref := "F-1a2b3c4d5e6f"
	planFinding, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005",
		"answered", AnsweredOpts{Reason: &tell, Anchor: strPtr("consumer"),
			Finding: &ref})
	if err != nil {
		t.Fatalf("a filed --finding must pass: %v", err)
	}
	if got := validation.ObjStr(probePriority(t, planFinding, "Q-005"),
		"interim_finding"); got != ref {
		t.Errorf("interim_finding = %q, want %q", got, ref)
	}

	// (d) negative control: the same consumer-anchor closure on a clean
	// reason is untouched
	clean := "commitBatch re-derives the root itself"
	if _, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &clean, Anchor: strPtr("consumer")}); err != nil {
		t.Fatalf("clean consumer-anchor closure must pass: %v", err)
	}

	// (e) negative control: the tell on a LOW-risk row passes — the trigger
	// is the row's risk, not the words alone
	lowRow := dgLowRow(t)
	lowSurface := validation.VObj(kv("rows", validation.VArr(lowRow)))
	withProbes(t, probeEnv{surface: &lowSurface, index: index})
	lowCamp := newCampaign(t, "dc-vocab-low")
	lowPlan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	lowPlan.O = validation.SetOrAppend(lowPlan.O, "priorities", validation.VArr(
		append(listOf(lowPlan, "priorities"),
			probePriorityVal("Q-100", "open", "", "0000000001"))...))
	if _, err := MarkAnswered(lowCamp, lowPlan, "Q-100", "answered",
		AnsweredOpts{Reason: &tell, Anchor: strPtr("consumer")}); err != nil {
		t.Fatalf("low-risk tell closure must pass without pricing: %v", err)
	}

	// (f) the override answers the vocabulary refusal: closes with exactly
	// one probe.dismissal_overridden (the row is off the axis here too, so
	// the refusal being answered is the lexical one)
	surface2, index2 := maSurface(t)
	withProbes(t, probeEnv{surface: dgSurfaceOffAxis(t, surface2, "81dfad6492",
		"guard-short-circuit"), index: index2})
	overCamp := newCampaign(t, "dc-vocab-override")
	why := "the operator accepts the interim window in writing for this run"
	logged := false
	if _, err := MarkAnswered(overCamp, deepCopy(t, plan), "Q-005",
		"answered", AnsweredOpts{Reason: &tell, Anchor: strPtr("consumer"),
			OverrideDismissal: true, OverrideReason: &why, Actor: "operator",
			OverrideLogged: &logged}); err != nil {
		t.Fatalf("override with reason must pass: %v", err)
	}
	if !logged {
		t.Error("OverrideLogged not set — the override went unannounced")
	}
	evts, err := overCamp.Events()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want exactly 1", n)
	}
}

// TestConsequenceFlagsAlwaysValidated pins FIX-2: --finding and --interim are
// validated on EVERY closure — any status, any priority, probe row or not.
// A ghost or malformed --finding and a statement too short to be one were
// previously inert off the deferred gate's rows: recorded verbatim or dropped
// without a word.
func TestConsequenceFlagsAlwaysValidated(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "dc-flags")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	// a plain (non-probe) priority: no gate covers it — the flags must still
	// not be inert
	plain := validation.VObj(kv("id", validation.VStr("Q-900")),
		kv("question", validation.VStr(
			"the drain-capable role is a single multisig, not reachable")),
		kv("risk", validation.VFloat(0.5)),
		kv("trajectories", validation.VArr(validation.VStr("economic"))),
		kv("status", validation.VStr("open")))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(
		append(listOf(plan, "priorities"), plain)...))
	reason := "the drain-capable role is a single multisig, not reachable"

	// (a) a ghost --finding on the plain priority: refused
	ghost := "F-000000000000"
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, Finding: &ghost})
	if err == nil || !strings.Contains(err.Error(), "F-000000000000") ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("ghost --finding must be refused on a plain priority, "+
			"err = %v", err)
	}

	// (b) a malformed --finding: refused as one
	malformed := "the big one"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, Finding: &malformed})
	if err == nil || !strings.Contains(err.Error(), "is not a finding id") {
		t.Fatalf("malformed --finding must be refused, err = %v", err)
	}

	// (c) a TERMINAL finding: refused — it records nothing about a window
	// that is still open
	terminalID := "F-aaaaaaaaaaaa"
	if err := os.MkdirAll(camp.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(camp.FindingsDir,
		terminalID+".json"),
		[]byte(`{"finding_id":"`+terminalID+`","status":"DISPROVED"}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, Finding: &terminalID})
	if err == nil || !strings.Contains(err.Error(), terminalID) ||
		!strings.Contains(err.Error(), "terminal") {
		t.Fatalf("terminal --finding must be refused, err = %v", err)
	}

	// (d) a live finding: passes, and is recorded
	dcSeedFinding(t, camp, "F-1a2b3c4d5e6f")
	live := "F-1a2b3c4d5e6f"
	planLive, err := MarkAnswered(camp, deepCopy(t, plan), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, Finding: &live})
	if err != nil {
		t.Fatalf("a live --finding must pass: %v", err)
	}
	var liveP validation.Value
	for _, q := range listOf(planLive, "priorities") {
		if validation.ObjStr(q, "id") == "Q-900" {
			liveP = q
		}
	}
	if got := validation.ObjStr(liveP, "interim_finding"); got != live {
		t.Errorf("interim_finding = %q, want %q", got, live)
	}

	// (e) an --interim too short to be a statement: refused
	plan2 := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	plan2.O = validation.SetOrAppend(plan2.O, "priorities", validation.VArr(
		append(listOf(plan2, "priorities"),
			deepCopy(t, plain))...))
	short := "no"
	_, err = MarkAnswered(camp, deepCopy(t, plan2), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, Interim: &short})
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("short --interim must be refused, err = %v", err)
	}

	// (f) a real statement on the plain priority: passes and is recorded
	statement := "the drain role stays single-key until the rotation lands"
	plan3, err := MarkAnswered(camp, deepCopy(t, plan2), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, Interim: &statement})
	if err != nil {
		t.Fatalf("a real --interim must pass: %v", err)
	}
	for _, q := range listOf(plan3, "priorities") {
		if validation.ObjStr(q, "id") == "Q-900" && validation.ObjStr(q, "interim") != statement {
			t.Errorf("interim = %q, want %q", validation.ObjStr(q, "interim"), statement)
		}
	}

	// (g) always means always: a REOPEN with a ghost --finding is refused
	// too, though no gate below would ever look at it
	plan4 := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	plan4.O = validation.SetOrAppend(plan4.O, "priorities", validation.VArr(
		append(listOf(plan4, "priorities"),
			deepCopy(t, plain))...))
	_, err = MarkAnswered(camp, plan4, "Q-900", "open",
		AnsweredOpts{Finding: &ghost})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("ghost --finding must be refused on a reopen, err = %v", err)
	}
}

// TestGateSkipNotice pins FIX-3: a disposition gate that cannot resolve the
// priority's probe row against the current surface (the surface was
// re-emitted after the closure was written) sets SkipNotice — naming the row
// and the gate — instead of skipping silently. resolveAnchor refuses the
// same condition on the apply path, so these are unit-level pins of the
// gates' stand-down contract.
func TestGateSkipNotice(t *testing.T) {
	surface, _ := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: nil})
	camp := newCampaign(t, "dc-skip-notice")
	prov := validation.VObj(kv("row_id", validation.VStr("9999999999")))

	notice := ""
	if err := checkSentinelPassesRow(camp, "Q-005", "answered", prov, true,
		AnsweredOpts{Anchor: strPtr("consumer"), SkipNotice: &notice},
		false); err != nil {
		t.Fatalf("sentinel gate must skip, not fail: %v", err)
	}
	for _, want := range []string{"9999999999", "Q-005",
		"not in the current surface", "sentinel-guard gate was skipped"} {
		if !strings.Contains(notice, want) {
			t.Errorf("sentinel notice missing %q: %q", want, notice)
		}
	}

	notice = ""
	if err := checkDeferredConsequenceRow(camp, "Q-005", "answered", prov,
		true, AnsweredOpts{Anchor: strPtr("consumer"), SkipNotice: &notice},
		false); err != nil {
		t.Fatalf("deferred gate must skip, not fail: %v", err)
	}
	for _, want := range []string{"9999999999",
		"not in the current surface",
		"deferred-consequence gate was skipped"} {
		if !strings.Contains(notice, want) {
			t.Errorf("deferred notice missing %q: %q", want, notice)
		}
	}

	notice = ""
	if err := checkDismissalGateInner(camp, "Q-005", "answered", prov, true,
		AnsweredOpts{Reason: strPtr("clean reason"), SkipNotice: &notice},
		false); err != nil {
		t.Fatalf("dismissal gate must skip, not fail: %v", err)
	}
	for _, want := range []string{"9999999999",
		"not in the current surface", "dismissal gate was skipped"} {
		if !strings.Contains(notice, want) {
			t.Errorf("dismissal notice missing %q: %q", want, notice)
		}
	}

	// a RESOLVABLE row sets no notice: the skip is the unresolvable row's
	// fact, not the gate's mood
	row := dgRow81(t)
	resolvable := validation.VObj(kv("row_id",
		validation.VStr(validation.ObjStr(row, "row_id"))))
	notice = ""
	if err := checkDismissalGateInner(camp, "Q-005", "answered", resolvable,
		true, AnsweredOpts{Reason: strPtr("commitBatch re-derives the " +
			"root itself"), SkipNotice: &notice},
		false); err != nil {
		t.Fatalf("resolvable row must pass the gate: %v", err)
	}
	if notice != "" {
		t.Errorf("resolvable row set a notice: %q", notice)
	}
}

// TestDeferredConsequenceReviewSkipsUnresolvable pins FIX-3's sweep half: a
// closed tell-bearing row the current surface no longer ranks is returned in
// the skipped list ("PRIORITY (probe row ROWID)"), never silently dropped.
func TestDeferredConsequenceReviewSkipsUnresolvable(t *testing.T) {
	surface, _ := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: nil})
	camp := newCampaign(t, "dc-review-skip")
	tell := "the row stays unfinalizable until the asserter runs"
	plan := validation.VObj(kv("priorities", validation.VArr(
		probePriorityVal("Q-210", "answered", tell, "81dfad6492"),
		probePriorityVal("Q-211", "answered", tell, "0000000001"),
	)))
	// the re-emitted surface: neither row is in it anymore
	ghost := validation.VObj(kv("rows", validation.VArr()))
	withProbes(t, probeEnv{surface: &ghost, index: nil})

	flags, skipped, err := DeferredConsequenceReview(camp, plan)
	if err != nil {
		t.Fatalf("DeferredConsequenceReview: %v", err)
	}
	if len(flags) != 0 {
		t.Fatalf("flags = %+v, want none (nothing is rankable)", flags)
	}
	if len(skipped) != 2 ||
		skipped[0] != "Q-210 (probe row 81dfad6492)" ||
		skipped[1] != "Q-211 (probe row 0000000001)" {
		t.Fatalf("skipped = %+v, want both closures named", skipped)
	}
}

// TestLowRiskOverrideRecordsEvent pins FIX-8: an explicit --override-dismissal
// with a justification on a NON-high-risk, non-sentinel probe row is logged —
// exactly one probe.dismissal_overridden, with the row's own provenance and
// an empty phrase list (the dismissal vocabulary never fired). The bare
// override is refused, the pre-flight records nothing, and a sentinel-form
// low-risk row still carries exactly one event (the sentinel arm's).
func TestLowRiskOverrideRecordsEvent(t *testing.T) {
	t.Setenv("WEBV2_NOW", "2026-09-09T12:00:00.000000+00:00")
	lowRow := dgLowRow(t)
	lowSurface := validation.VObj(kv("rows", validation.VArr(lowRow)))
	withProbes(t, probeEnv{surface: &lowSurface, index: nil})
	camp := newCampaign(t, "dc-low-override")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(
		append(listOf(plan, "priorities"),
			probePriorityVal("Q-100", "open", "", "0000000001"))...))
	why := "the operator accepts the risk in writing for this run"
	reason := "commitBatch re-derives the root itself"

	// (a) bare override on a low-risk non-sentinel row: refused — it used to
	// exit 0 with no event and no notice
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-100", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true})
	if err == nil || !strings.Contains(err.Error(),
		"--override-dismissal needs --override-reason") {
		t.Fatalf("bare override must be refused, err = %v", err)
	}

	// (b) override with a reason: closes with exactly one event
	logged := false
	if _, err := MarkAnswered(camp, deepCopy(t, plan), "Q-100", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true, OverrideReason: &why, Actor: "operator",
			OverrideLogged: &logged}); err != nil {
		t.Fatalf("override with reason must pass: %v", err)
	}
	if !logged {
		t.Error("OverrideLogged not set — the override went unannounced")
	}
	evts, err := camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	var logged1 []validation.Value
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			logged1 = append(logged1, e)
		}
	}
	if len(logged1) != 1 {
		t.Fatalf("probe.dismissal_overridden events = %d, want exactly 1",
			len(logged1))
	}
	data := validation.ObjAt(logged1[0], "data")
	if got := validation.ObjStr(data, "row_id"); got != "0000000001" {
		t.Errorf("row_id = %q", got)
	}
	if got := validation.ObjAt(data, "tier").I; got != 2 {
		t.Errorf("tier = %d, want 2", got)
	}
	if got := validation.ObjAt(data, "assertion_gap").I; got != 1 {
		t.Errorf("assertion_gap = %d, want 1", got)
	}
	if got := validation.ObjStr(data, "actor"); got != "operator" {
		t.Errorf("actor = %q, want operator", got)
	}
	if got := validation.ObjStr(data, "override_reason"); got != why {
		t.Errorf("override_reason = %q", got)
	}
	if got := validation.ObjStr(data, "closed_reason"); got != reason {
		t.Errorf("closed_reason = %q", got)
	}
	if validation.ObjAt(data, "phrases").Kind == validation.Arr &&
		len(validation.ObjAt(data, "phrases").A) != 0 {
		t.Errorf("phrases = %+v, want empty (no dismissal vocabulary fired)",
			validation.ObjAt(data, "phrases").A)
	}

	// (c) the pre-flight records nothing, but the notice out-param is set
	logged2 := false
	if _, err := runAnsweredGates(camp, deepCopy(t, plan), "Q-100",
		"answered", AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true, OverrideReason: &why,
			OverrideLogged: &logged2}, true); err != nil {
		t.Fatalf("dry pre-flight must pass: %v", err)
	}
	if !logged2 {
		t.Error("dry pre-flight did not set OverrideLogged")
	}
	evts, err = camp.Events()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("dry pre-flight logged an event: %d total, want 1", n)
	}

	// (d) sentinel-form low-risk row: the sentinel arm (which runs first)
	// records the event, the dismissal gate's low-risk arm yields — still
	// exactly one
	sentLow := dgLowRow(t)
	sentLow.O = validation.SetOrAppend(sentLow.O, "own_form",
		validation.VStr("sentinel"))
	sentLow.O = validation.SetOrAppend(sentLow.O, "own_guard_text",
		validation.VStr("root != bytes32(0)"))
	sentSurface := validation.VObj(kv("rows", validation.VArr(sentLow)))
	withProbes(t, probeEnv{surface: &sentSurface, index: nil})
	sentCamp := newCampaign(t, "dc-low-override-sentinel")
	sentPlan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	sentPlan.O = validation.SetOrAppend(sentPlan.O, "priorities",
		validation.VArr(append(listOf(sentPlan, "priorities"),
			probePriorityVal("Q-100", "open", "", "0000000001"))...))
	if _, err := MarkAnswered(sentCamp, sentPlan, "Q-100", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			OverrideDismissal: true, OverrideReason: &why,
			Actor: "operator"}); err != nil {
		t.Fatalf("sentinel low-risk override must pass: %v", err)
	}
	evts, err = sentCamp.Events()
	if err != nil {
		t.Fatal(err)
	}
	n = 0
	for _, e := range evts {
		if validation.ObjStr(e, "type") == "probe.dismissal_overridden" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("sentinel low-risk override events = %d, want exactly 1", n)
	}
}

// TestSentinelPassesPlausibilityFloor pins FIX-C: --passes is not a rubber
// stamp. A value that clears the 3-character floor but is neither a row
// citation nor a concrete machine-checkable literal ("zzz", "TBD", "n/a")
// is refused with BOTH legal shapes named; either legal shape is accepted
// and recorded. The refusal is a decision that did not happen.
func TestSentinelPassesPlausibilityFloor(t *testing.T) {
	camp, _, rowID := sentinelDispositionFixture(t)

	// (a) junk: neither shape, refused with both shapes named
	for _, junk := range []string{"zzz", "TBD", "n/a", "maybe"} {
		_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
			&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &junk})
		if err == nil || !strings.Contains(err.Error(),
			"is not a plausible value for the check") {
			t.Fatalf("junk --passes %q must be refused: %v", junk, err)
		}
		if !strings.Contains(err.Error(), "row's own surface entry") ||
			!strings.Contains(err.Error(), "concrete literal") {
			t.Errorf("refusal does not name both legal shapes for %q:\n%v",
				junk, err)
		}
		// negative control: the refusal is a decision that did not happen
		prio := storedPriority(t, camp, rowID)
		if got := validation.ObjStr(prio, "status"); got != "open" {
			t.Fatalf("junk %q refusal changed the status to %q", junk, got)
		}
		if validation.ObjAt(prio, "passes").Kind != validation.Null {
			t.Fatalf("junk %q refusal recorded passes = %q", junk,
				validation.ObjStr(prio, "passes"))
		}
	}

	// (b) legal shape 1: the value names a symbol on the row's own surface
	// entry (the citation muscle). morph §6.1/§7.1: the enforcement-timing
	// row owes the interim pricing as well — the plausibility floor under
	// test runs first, and pricing keeps this arm on it.
	cite := "asserted at finalizeBatch"
	floorInterim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &cite,
			Interim: &floorInterim})
	if err != nil {
		t.Fatalf("row-citation --passes must pass: %v", err)
	}
	if got := validation.ObjStr(storedPriority(t, camp, rowID), "passes"); got != cite {
		t.Errorf("passes = %q, want %q", got, cite)
	}

	// (c) legal shape 2: a concrete machine-checkable literal — recorded
	// verbatim and re-checkable by any reader (a hex literal is trusted as
	// a claimed value; that is the record-not-answer contract)
	for _, literal := range []string{"0xdeadbeef", "1000", "bytes32(0x" +
		"0000000000000000000000000000000000000000000000000000000000000001)",
		"true", `"finalized"`} {
		_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
			&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &literal,
				Interim: &floorInterim})
		if err != nil {
			t.Fatalf("literal --passes %q must pass: %v", literal, err)
		}
		if got := validation.ObjStr(storedPriority(t, camp, rowID), "passes"); got != literal {
			t.Errorf("passes = %q, want %q", got, literal)
		}
	}
}
