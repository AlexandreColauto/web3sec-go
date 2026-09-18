package findings

// amend_test.go: G14a amend/supersede store tests — version/history/event
// discipline, evidence re-parenting, and the supersede gates.

import (
	"errors"
	"strings"
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
	return c, validation.ObjStr(f, "finding_id")
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
	hist := validation.ObjAt(f, "history")
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
		if validation.ObjStr(e, "type") == typ {
			return e
		}
	}
	t.Fatalf("event %s missing", typ)
	return validation.VNull()
}

// assertNoStatusEvent locks amend law 1 from the event side: no
// finding.status event may exist after an amend (a from == to status
// "transition" is a lie the hash chain must never carry).
func assertNoStatusEvent(t *testing.T, c *state.Campaign) {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.status" {
			t.Fatalf("amend emitted finding.status (ref %s) — amend "+
				"must never move status", validation.ObjStr(e, "ref"))
		}
	}
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
	if st := validation.ObjStr(got, "status"); st != "HYPOTHESIS" {
		t.Fatalf("amend moved status to %q", st)
	}
	if v := validation.ObjAt(got, "claim_version"); v.Kind != validation.Int || v.I != 1 {
		t.Fatalf("claim_version = %v, want 1", v)
	}
	if title := validation.ObjStr(got, "title"); title != "User can withdraw more "+
		"than deposited via rounding tricks" {
		t.Fatalf("title = %q", title)
	}
	last := lastHistory(t, got)
	if validation.ObjStr(last, "from") != "HYPOTHESIS" || validation.ObjStr(last, "to") != "HYPOTHESIS" {
		t.Fatalf("history from/to = %q/%q, want HYPOTHESIS/HYPOTHESIS",
			validation.ObjStr(last, "from"), validation.ObjStr(last, "to"))
	}
	wantReason := "amend: title — retitled after reading the vault code"
	if validation.ObjStr(last, "reason") != wantReason {
		t.Fatalf("history reason = %q, want %q", validation.ObjStr(last, "reason"),
			wantReason)
	}
	if validation.ObjStr(last, "actor") != "model" {
		t.Fatalf("history actor = %q, want model", validation.ObjStr(last, "actor"))
	}
	e := hasEvent(t, c, "finding.amended")
	if validation.ObjStr(validation.ObjAt(e, "data"), "reason") != wantReason {
		t.Errorf("finding.amended reason = %q, want %q",
			validation.ObjStr(validation.ObjAt(e, "data"), "reason"), wantReason)
	}
	// Law 1: amend never moves status, so it emits no finding.status
	// event (ingest logs finding.ingested, not finding.status — any
	// finding.status event here would be the amend's lie).
	assertNoStatusEvent(t, c)
	// A second amend bumps again.
	got, err = Amend(c, fid, AmendOpts{
		Claim:    "share calculation rounds down in the attacker's favor always",
		HasClaim: true,
		Actor:    "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := validation.ObjAt(got, "claim_version"); v.Kind != validation.Int || v.I != 2 {
		t.Fatalf("claim_version = %v, want 2", v)
	}
	if desc := validation.ObjStr(validation.ObjAt(got, "root_cause"), "description"); desc !=
		"share calculation rounds down in the attacker's favor always" {
		t.Fatalf("root_cause.description = %q", desc)
	}
	last = lastHistory(t, got)
	if validation.ObjStr(last, "reason") != "amend: claim" {
		t.Fatalf("history reason = %q, want %q", validation.ObjStr(last, "reason"),
			"amend: claim")
	}
	if validation.ObjStr(last, "actor") != "cli" {
		t.Fatalf("history actor = %q, want cli", validation.ObjStr(last, "actor"))
	}
	// Still no finding.status event after the second amend.
	assertNoStatusEvent(t, c)
}

func TestAmendNoteOnly(t *testing.T) {
	c, fid := amendCamp(t)
	got, err := Amend(c, fid, AmendOpts{Note: "reviewer asked for clarity"})
	if err != nil {
		t.Fatal(err)
	}
	if v := validation.ObjAt(got, "claim_version"); v.Kind != validation.Int || v.I != 1 {
		t.Fatalf("claim_version = %v, want 1", v)
	}
	if reason := validation.ObjStr(lastHistory(t, got), "reason"); reason !=
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
	if v := validation.ObjAt(got, "claim_version"); v.Kind != validation.Null {
		t.Fatalf("rejected amend wrote claim_version = %v", v)
	}
	if hist := validation.ObjAt(got, "history"); hist.Kind != validation.Arr ||
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
	if cls := validation.ObjStr(validation.ObjAt(got, "root_cause"), "class"); cls != "logic-error" {
		t.Fatalf("root_cause.class = %q", cls)
	}
	if reason := validation.ObjStr(lastHistory(t, got), "reason"); reason != "amend: class" {
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
	if cls := validation.ObjStr(validation.ObjAt(got, "root_cause"), "class"); cls != "logic-error" {
		t.Fatalf("rejected class overwrote root_cause.class = %q", cls)
	}
	if v := validation.ObjAt(got, "claim_version"); v.Kind != validation.Int || v.I != 1 {
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
	beforeEv := validation.CanonSpaced(validation.ObjAt(before, "evidence"))
	var newID string
	{
		f, err := IngestHypothesis(c, hypoPayload(
			kv("title", validation.VStr("ShareVault restated inflation"))),
			"code", "", "")
		if err != nil {
			t.Fatal(err)
		}
		newID = validation.ObjStr(f, "finding_id")
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
	if st := validation.ObjStr(old, "status"); st != "SUPERSEDED" {
		t.Fatalf("old status = %q, want SUPERSEDED", st)
	}
	last := lastHistory(t, old)
	if validation.ObjStr(last, "to") != "SUPERSEDED" {
		t.Fatalf("old history to = %q", validation.ObjStr(last, "to"))
	}
	if validation.ObjStr(last, "reason") != "superseded by "+newID {
		t.Fatalf("old history reason = %q", validation.ObjStr(last, "reason"))
	}
	// Old evidence array byte-equal pre/post (append-only store).
	if after := validation.CanonSpaced(validation.ObjAt(old, "evidence")); after != beforeEv {
		t.Fatalf("old evidence mutated:\nbefore %s\nafter  %s", beforeEv, after)
	}
	// New finding: copies stamped re_parented_from + dedup_meta.supersedes.
	ev := validation.ObjAt(got, "evidence")
	if len(ev.A) != 2 {
		t.Fatalf("new evidence has %d items, want 2", len(ev.A))
	}
	for _, it := range ev.A {
		if validation.ObjStr(it, "re_parented_from") != oldID {
			t.Errorf("copied item %s missing re_parented_from",
				validation.ObjStr(it, "evidence_id"))
		}
	}
	ids := map[string]bool{}
	for _, it := range ev.A {
		ids[validation.ObjStr(it, "evidence_id")] = true
	}
	if !ids["EV-aaa"] || !ids["EV-aab"] {
		t.Fatalf("copied evidence ids = %v", ids)
	}
	if sup := validation.ObjStr(validation.ObjAt(got, "dedup_meta"), "supersedes"); sup != oldID {
		t.Fatalf("dedup_meta.supersedes = %q, want %q", sup, oldID)
	}
	e := hasEvent(t, c, "finding.superseded")
	if validation.ObjStr(validation.ObjAt(e, "data"), "old") != oldID {
		t.Errorf("finding.superseded old = %q", validation.ObjStr(validation.ObjAt(e, "data"), "old"))
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
	newID := validation.ObjStr(nf, "finding_id")
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
	if _, ok := fieldAt(validation.ObjAt(got, "dedup_meta"), "supersedes"); ok {
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

// TestAmendClassRaiseConvertsNotRefuses pins the r3 law: an E4 finding
// re-classed to a stricter-floor class AMENDS freely (the advisory's own
// advice) — the status stands and the gate now owes mandatory verification
// work (deficit visible on every read, never silent).
func TestAmendClassRaiseConvertsNotRefuses(t *testing.T) {
	withKnownClasses(t, "precision-rounding", "oracle-manipulation",
		"access-control")
	c, fid := amendCamp(t)
	f, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "status", validation.VStr("CONFIRMED"))
	f.O = validation.SetOrAppend(f.O, "evidence", validation.VArr(
		validation.VObj(
			kv("evidence_id", validation.VStr("EV-f3")),
			kv("level", validation.VStr("E4")),
			kv("type", validation.VStr("foundry-test")),
			kv("description", validation.VStr("local PoC drained it")),
		)))
	if err := SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	if _, err := Amend(c, fid, AmendOpts{Class: "oracle-manipulation",
		HasClass: true}); err != nil {
		t.Fatalf("the advisory tells operators to re-file by true class: %v", err)
	}
	after, _ := LoadFinding(c, fid)
	if st := validation.ObjStr(after, "status"); st != "CONFIRMED" {
		t.Fatalf("status must stand (conversion, not invalidation): %q", st)
	}
	if d := EvidenceDeficit(after, "CONFIRMED", c); d == nil {
		t.Fatal("the raised E5 floor must be a VISIBLE deficit after the amend")
	}
}

// TestSupersedeTwoCycleRefused pins critic r3: after A supersedes B, B is
// SUPERSEDED — and a terminal finding cannot adopt anything, so B -> A is
// refused. The pair can never retire onto each other into zero live rows.
func TestSupersedeTwoCycleRefused(t *testing.T) {
	withKnownClasses(t, "precision-rounding")
	c := ingestCamp(t)
	fa, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fb, err := IngestHypothesis(c, hypoPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	idA, idB := validation.ObjStr(fa, "finding_id"), validation.ObjStr(fb, "finding_id")
	if _, err := Supersede(c, idA, idB, "model"); err != nil {
		t.Fatalf("first supersede A-of-B: %v", err)
	}
	_, err = Supersede(c, idB, idA, "model")
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("the cycle-back must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "terminal finding") ||
		!strings.Contains(err.Error(), "cycle") {
		t.Fatalf("refusal must name terminality and the cycle: %v", err)
	}
	// A is still live and holds the family.
	a, _ := LoadFinding(c, idA)
	if st := validation.ObjStr(a, "status"); st != "HYPOTHESIS" {
		t.Fatalf("successor status after refusal = %q", st)
	}
}
