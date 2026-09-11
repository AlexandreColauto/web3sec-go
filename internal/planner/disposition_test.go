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
	row.O = validation.SetOrAppend(row.O, "row_id", validation.VStr("0000000001"))
	row.O = validation.SetOrAppend(row.O, "tier", validation.VInt(2))
	row.O = validation.SetOrAppend(row.O, "assertion_gap", validation.VInt(1))
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

	// (c) an EXEC id with no record on disk: rejected as a FABRICATED
	// citation — v3 answers this before the anchor rule, because "no such
	// exec record" is more useful than "that is not the anchor it claims"
	refGhost := "EXEC-0000000000"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &refGhost})
	if err == nil || !strings.Contains(err.Error(), "which does not exist") {
		t.Fatalf("ghost EXEC ref must be rejected as fabricated, err = %v", err)
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

	// (g) v3: clean prose that names nothing from the row is refused too. The
	// vocabulary table (v2) catches the historical wording; this catches its
	// substitutes — a reason that could have been written without opening the
	// file is not a disposition, it is a hope.
	vague := "the whole thing looked fine when I traced it"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &vague, Anchor: strPtr("consumer")})
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
		AnsweredOpts{Reason: &cited, Anchor: strPtr("consumer")})
	if err != nil {
		t.Fatalf("a cited reason must pass: %v", err)
	}
	if got := objStr(probePriority(t, planCited, "Q-005"), "closed_reason"); got != cited {
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
	logged := false
	_, err := MarkAnswered(camp, deepCopy(t, maPlan(t, "plan_probe_rows.json")),
		"Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &ref,
			OverrideLogged: &logged})
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
		if objStr(e, "type") == "probe.dismissal_overridden" {
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
		if objStr(r, "row_id") == "81dfad6492" {
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
		if objStr(r, "row_id") != "81dfad6492" {
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
			objStr(prov, "row_id") == objStr(row, "row_id") {
			pid = objStr(p, "id")
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
	// to cite the row, which it does)
	ok := "the F-1 code path and INV-x never converge inside commitBatch"
	if _, err := MarkAnswered(camp, deepCopy(t, plan), pid, "answered",
		AnsweredOpts{Reason: &ok, Anchor: strPtr("consumer")}); err != nil {
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
		if objStr(r, "row_id") != rowID {
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
			objStr(prov, "row_id") == rowID {
			return objStr(p, "id")
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
	_, _, err = plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &passes})
	if err != nil {
		t.Fatalf("with --passes: %v", err)
	}
	prio := storedPriority(t, camp, rowID)
	if objStr(prio, "passes") != passes {
		t.Errorf("passes = %q", objStr(prio, "passes"))
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
	if got := objStr(prio, "status"); got != "answered" {
		t.Errorf("status = %q, want answered", got)
	}
	if got := objStr(prio, "passes"); got != "" {
		t.Errorf("passes = %q, want none (the override is the record)", got)
	}
}
