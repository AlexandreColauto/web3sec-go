package findings

// amend_test.go: G14a amend/supersede store tests — version/history/event
// discipline, evidence re-parenting, and the supersede gates.

import (
	"errors"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// amendCamp ingests one HYPOTHESIS finding and returns the campaign + id.
func amendCamp(t *testing.T, over ...validation.KV) (*state.Campaign, string) {
	t.Helper()
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(over...), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return c, objStr(f, "finding_id")
}

// withKnownClasses wires the taxonomy seam to a fixed vocabulary,
// restored after the test (the planner's init wires the real one for the
// CLI; the findings package must not import taxonomy — import cycle).
func withKnownClasses(t *testing.T, classes ...string) {
	t.Helper()
	prev := taxonomyKnownClassesFunc
	set := map[string]struct{}{}
	for _, cl := range classes {
		set[cl] = struct{}{}
	}
	taxonomyKnownClassesFunc = func() map[string]struct{} { return set }
	t.Cleanup(func() { taxonomyKnownClassesFunc = prev })
}

func lastHistory(t *testing.T, f validation.Value) validation.Value {
	t.Helper()
	hist := objAt(f, "history")
	if hist.Kind != validation.Arr || len(hist.A) == 0 {
		t.Fatal("history is empty")
	}
	return hist.A[len(hist.A)-1]
}

func hasEvent(t *testing.T, c *state.Campaign, typ string) validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if objStr(e, "type") == typ {
			return e
		}
	}
	t.Fatalf("event %s missing", typ)
	return validation.VNull()
}

func TestSupersededStateMachine(t *testing.T) {
	if _, ok := TERMINAL["SUPERSEDED"]; !ok {
		t.Error("SUPERSEDED must join the TERMINAL absorbing set")
	}
	for _, from := range []string{"HYPOTHESIS", "NEEDS_RESEARCH",
		"PROVISIONALLY_VALID", "POSSIBLE", "CONFIRMED", "CHAIN"} {
		if !TransitionAllowed(from, "SUPERSEDED") {
			t.Errorf("%s -> SUPERSEDED must be allowed", from)
		}
		if TransitionAllowed("SUPERSEDED", from) {
			t.Errorf("SUPERSEDED -> %s must be refused (absorbing)", from)
		}
	}
	for _, term := range []string{"DISPROVED", "OUT_OF_SCOPE",
		"INFORMATIONAL", "DUPLICATE"} {
		if TransitionAllowed(term, "SUPERSEDED") {
			t.Errorf("terminal %s -> SUPERSEDED must be refused", term)
		}
	}
	if len(ALLOWED_TRANSITIONS["SUPERSEDED"]) != 0 {
		t.Error("SUPERSEDED table entry must be the empty set")
	}
	// Floor: SUPERSEDED absorbs like OUT_OF_SCOPE — no STATUS_FLOOR row,
	// so the default E0 applies.
	if _, ok := STATUS_FLOOR["SUPERSEDED"]; ok {
		t.Error("SUPERSEDED must not carry a STATUS_FLOOR row")
	}
	if got := RequiredLevelFor("SUPERSEDED", "reentrancy"); got != "E0" {
		t.Errorf("SUPERSEDED floor = %q, want E0", got)
	}
}

func TestAmendBumpsVersionHistoryAndEvent(t *testing.T) {
	c, fid := amendCamp(t)
	got, err := Amend(c, fid, AmendOpts{
		Title:    "User can withdraw more than deposited via rounding tricks",
		HasTitle: true,
		Note:     "retitled after reading the vault code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(got, "status"); st != "HYPOTHESIS" {
		t.Fatalf("amend moved status to %q", st)
	}
	if v := objAt(got, "claim_version"); v.Kind != validation.Int || v.I != 1 {
		t.Fatalf("claim_version = %v, want 1", v)
	}
	if title := objStr(got, "title"); title != "User can withdraw more "+
		"than deposited via rounding tricks" {
		t.Fatalf("title = %q", title)
	}
	last := lastHistory(t, got)
	if objStr(last, "from") != "HYPOTHESIS" || objStr(last, "to") != "HYPOTHESIS" {
		t.Fatalf("history from/to = %q/%q, want HYPOTHESIS/HYPOTHESIS",
			objStr(last, "from"), objStr(last, "to"))
	}
	wantReason := "amend: title — retitled after reading the vault code"
	if objStr(last, "reason") != wantReason {
		t.Fatalf("history reason = %q, want %q", objStr(last, "reason"),
			wantReason)
	}
	if objStr(last, "actor") != "model" {
		t.Fatalf("history actor = %q, want model", objStr(last, "actor"))
	}
	e := hasEvent(t, c, "finding.amended")
	if objStr(objAt(e, "data"), "reason") != wantReason {
		t.Errorf("finding.amended reason = %q, want %q",
			objStr(objAt(e, "data"), "reason"), wantReason)
	}
	// A second amend bumps again.
	got, err = Amend(c, fid, AmendOpts{
		Claim:    "share calculation rounds down in the attacker's favor always",
		HasClaim: true,
		Actor:    "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := objAt(got, "claim_version"); v.Kind != validation.Int || v.I != 2 {
		t.Fatalf("claim_version = %v, want 2", v)
	}
	if desc := objStr(objAt(got, "root_cause"), "description"); desc !=
		"share calculation rounds down in the attacker's favor always" {
		t.Fatalf("root_cause.description = %q", desc)
	}
	last = lastHistory(t, got)
	if objStr(last, "reason") != "amend: claim" {
		t.Fatalf("history reason = %q, want %q", objStr(last, "reason"),
			"amend: claim")
	}
	if objStr(last, "actor") != "cli" {
		t.Fatalf("history actor = %q, want cli", objStr(last, "actor"))
	}
}

func TestAmendNoteOnly(t *testing.T) {
	c, fid := amendCamp(t)
	got, err := Amend(c, fid, AmendOpts{Note: "reviewer asked for clarity"})
	if err != nil {
		t.Fatal(err)
	}
	if v := objAt(got, "claim_version"); v.Kind != validation.Int || v.I != 1 {
		t.Fatalf("claim_version = %v, want 1", v)
	}
	if reason := objStr(lastHistory(t, got), "reason"); reason !=
		"amend: note — reviewer asked for clarity" {
		t.Fatalf("history reason = %q", reason)
	}
}

func TestAmendNoFlagRejected(t *testing.T) {
	c, fid := amendCamp(t)
	_, err := Amend(c, fid, AmendOpts{})
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("want RejectedError, got %v", err)
	}
	// Nothing was written: no version, and history still holds only the
	// single ingest entry.
	got, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if v := objAt(got, "claim_version"); v.Kind != validation.Null {
		t.Fatalf("rejected amend wrote claim_version = %v", v)
	}
	if hist := objAt(got, "history"); hist.Kind != validation.Arr ||
		len(hist.A) != 1 {
		t.Fatalf("rejected amend touched history: %v", hist)
	}
}

func TestAmendClassCanonicalization(t *testing.T) {
	withKnownClasses(t, "reentrancy", "logic-error")
	c, fid := amendCamp(t)
	got, err := Amend(c, fid, AmendOpts{Class: "logic-error", HasClass: true})
	if err != nil {
		t.Fatal(err)
	}
	if cls := objStr(objAt(got, "root_cause"), "class"); cls != "logic-error" {
		t.Fatalf("root_cause.class = %q", cls)
	}
	if reason := objStr(lastHistory(t, got), "reason"); reason != "amend: class" {
		t.Fatalf("history reason = %q", reason)
	}
	_, err = Amend(c, fid, AmendOpts{Class: "vibes-based", HasClass: true})
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("unknown class: want RejectedError, got %v", err)
	}
	// The rejected class never landed.
	got, err = LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if cls := objStr(objAt(got, "root_cause"), "class"); cls != "logic-error" {
		t.Fatalf("rejected class overwrote root_cause.class = %q", cls)
	}
	if v := objAt(got, "claim_version"); v.Kind != validation.Int || v.I != 1 {
		t.Fatalf("rejected amend bumped claim_version = %v", v)
	}
}

func amendEvidenceItem(id, level, typ, desc string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(id)),
		kv("level", validation.VStr(level)),
		kv("type", validation.VStr(typ)),
		kv("description", validation.VStr(desc)),
	)
}

func TestSupersedeHappyPath(t *testing.T) {
	c, oldID := amendCamp(t)
	if _, err := AddEvidence(c, oldID, amendEvidenceItem("EV-aaa",
		"E1", "reasoning", "the deposit path has no share-price guard")); err != nil {
		t.Fatal(err)
	}
	if _, err := AddEvidence(c, oldID, amendEvidenceItem("EV-aab",
		"E2", "reachability", "empty-vault first deposit is reachable")); err != nil {
		t.Fatal(err)
	}
	before, err := LoadFinding(c, oldID)
	if err != nil {
		t.Fatal(err)
	}
	beforeEv := validation.CanonSpaced(objAt(before, "evidence"))
	var newID string
	{
		f, err := IngestHypothesis(c, hypoPayload(
			kv("title", validation.VStr("ShareVault restated inflation"))),
			"code", "", "")
		if err != nil {
			t.Fatal(err)
		}
		newID = objStr(f, "finding_id")
	}
	got, err := Supersede(c, newID, oldID, "model")
	if err != nil {
		t.Fatal(err)
	}
	// Old finding transitioned through Transition: status + history + event.
	old, err := LoadFinding(c, oldID)
	if err != nil {
		t.Fatal(err)
	}
	if st := objStr(old, "status"); st != "SUPERSEDED" {
		t.Fatalf("old status = %q, want SUPERSEDED", st)
	}
	last := lastHistory(t, old)
	if objStr(last, "to") != "SUPERSEDED" {
		t.Fatalf("old history to = %q", objStr(last, "to"))
	}
	if objStr(last, "reason") != "superseded by "+newID {
		t.Fatalf("old history reason = %q", objStr(last, "reason"))
	}
	// Old evidence array byte-equal pre/post (append-only store).
	if after := validation.CanonSpaced(objAt(old, "evidence")); after != beforeEv {
		t.Fatalf("old evidence mutated:\nbefore %s\nafter  %s", beforeEv, after)
	}
	// New finding: copies stamped re_parented_from + dedup_meta.supersedes.
	ev := objAt(got, "evidence")
	if len(ev.A) != 2 {
		t.Fatalf("new evidence has %d items, want 2", len(ev.A))
	}
	for _, it := range ev.A {
		if objStr(it, "re_parented_from") != oldID {
			t.Errorf("copied item %s missing re_parented_from",
				objStr(it, "evidence_id"))
		}
	}
	ids := map[string]bool{}
	for _, it := range ev.A {
		ids[objStr(it, "evidence_id")] = true
	}
	if !ids["EV-aaa"] || !ids["EV-aab"] {
		t.Fatalf("copied evidence ids = %v", ids)
	}
	if sup := objStr(objAt(got, "dedup_meta"), "supersedes"); sup != oldID {
		t.Fatalf("dedup_meta.supersedes = %q, want %q", sup, oldID)
	}
	e := hasEvent(t, c, "finding.superseded")
	if objStr(objAt(e, "data"), "old") != oldID {
		t.Errorf("finding.superseded old = %q", objStr(objAt(e, "data"), "old"))
	}
	// And the old finding's own SUPERSEDED transition event exists.
	hasEvent(t, c, "finding.status")
}

func TestSupersedeTerminalOldRefused(t *testing.T) {
	c, oldID := amendCamp(t)
	if _, err := Transition(c, oldID, "DISPROVED", "not a bug", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	nf, err := IngestHypothesis(c, hypoPayload(
		kv("title", validation.VStr("ShareVault restated inflation"))),
		"code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	newID := objStr(nf, "finding_id")
	_, err = Supersede(c, newID, oldID, "model")
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("terminal old: want RejectedError, got %v", err)
	}
	// The new finding is untouched.
	got, err := LoadFinding(c, newID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fieldAt(objAt(got, "dedup_meta"), "supersedes"); ok {
		t.Error("refused supersede wrote dedup_meta.supersedes")
	}
}

func TestSupersedeSelfRefused(t *testing.T) {
	c, fid := amendCamp(t)
	_, err := Supersede(c, fid, fid, "model")
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("self-supersede: want RejectedError, got %v", err)
	}
}
