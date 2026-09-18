package sections

// zz_r34_test.go — section 11, round 34, F1: THE ONE-PROOF-ONE-ROW RAIL'S
// OFF-SWITCH WAS AN EMPTY PROPERTY TITLE.
//
// reportProofCollisionBurn opened with
//
//	prop := validation.ObjStr(last, "property")
//	if prop == "" {
//	    return ""
//	}
//
// so an event whose property title was empty (or absent) switched the whole
// rail off AND, downstream, harness.DecideReport(rep, "") happily resolved
// the report's property_outcomes[""] entry: a chain-valid campaign whose
// report is keyed "" re-derived PROVEN-BOUNDED for EVERY invariant that
// claimed the blank title, and section 11 printed an unqualified blessing
// line per row. The verb refuses that shape OUTRIGHT, before it reads any
// report bytes (cli.verifyAutoprove: "verify --autoprove needs --property
// <exact title the prover gave the property> — attribution is exact-match by
// design"), so a title no bind can write cannot be attributed and the rung
// is not backed.
//
// The mutations below are exactly the auditor's: a report whose
// property_outcomes holds the empty key, and slot+event pairs built through
// the campaign's own writers (zzR32bCampaign / r33Rewire) that name that
// title — one row, then two rows over the one pinned proof, then the absent
// field. Before the fix every one of them audited OK with a blessing; the
// controls (a non-blank title, and a whitespace title the bind DOES accept)
// stay green on both sides of the fix.
//
// The same sweep closed the off-switch ONE FIELD OVER, the BLANK BOUND: for
// a property whose rollup is bound UNSTATED the bind writes bounded_k null
// and no proof sidecar, so recheckRegistryEvidence's bound arm compared
// nothing in both fields — while the display line's k falls back to the
// SLOT's proof.bounds.loop_bound. TestR34BoundUnstatedForgedKBurns is that
// repro: it printed k=999999 over a pinned report that states no bound, with
// the audit green.

import (
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// r34WantGreen asserts section 11 blessed the campaign and rendered iid's
// line unqualified.
func r34WantGreen(t *testing.T, v validation.Value, iid string) {
	t.Helper()
	if !validation.ObjAt(v, "ok").B {
		t.Fatalf("section 11 must stay green: %s", validation.CanonCompact(v))
	}
	line := r33LineFor(v, iid)
	if !strings.Contains(line, iid+": PROVEN-BOUNDED") ||
		strings.Contains(line, "UNBACKED") {
		t.Fatalf("%s's line = %q, want an unqualified blessing", iid, line)
	}
}

// TestR34BlankPropertySingleRowBurns is F1's single-row repro: ONE row whose
// (slot, event) pair names the empty title over a report keyed "". No bind
// can write that pair — the verb exits 2 on the empty --property before it
// opens the report — so the rung must burn naming the empty attribution
// instead of printing "INV-3: PROVEN-BOUNDED (miniprover, k=4, REPORT-…)".
func TestR34BlankPropertySingleRowBurns(t *testing.T) {
	c, _, _ := zzR32bCampaign(t, r33Body(""), "")
	v := r33Audit(t, c)
	r33WantBurn(t, v, "INV-3", "INV-3", "''",
		"no bind can write", "is not backed")
}

// TestR34BlankPropertyTwoRowsBurns is F1's collision repro: TWO rows claim
// the same blank title over the same pinned proof, which is the
// one-proof-one-row law's shape with the off-switch string. Both must burn —
// the LATER row as the collision (naming the first claimant, exactly as for
// any other title), the FIRST because the title it holds is unwritable — so
// no pair of rows can both display a blessing.
func TestR34BlankPropertyTwoRowsBurns(t *testing.T) {
	c, _, sha := zzR32bCampaign(t, r33Body(""), "")
	r33Rewire(t, c, "INV-4", sha, "", string(harness.ReportKind),
		harness.ReportExecLabel(sha))

	v := r33Audit(t, c)
	// The rail runs for the blank title exactly as for a non-blank one: the
	// later claimant burns as a collision against the earlier row.
	r33WantBurn(t, v, "INV-4", "INV-4", "already bound to INV-3",
		"one property's proof binds one invariant")
	// …and the first claimant does NOT keep a blessing: there is no
	// legitimate holder of a title no bind can write.
	r33WantBurn(t, v, "INV-3", "INV-3", "no bind can write")
}

// TestR34AbsentPropertyFieldBurns is F1's absence half: the property KEY is
// removed from the last harness_run event (objStr reads ""), while the report
// is keyed "". Absence is not "no claim" for a report rung — it is the same
// unwritable title — so the rung must burn rather than resolve
// property_outcomes[""].
func TestR34AbsentPropertyFieldBurns(t *testing.T) {
	c, _, _ := zzR32bCampaign(t, r33Body(""), "")
	zzR32bDropEventKey(t, c, "INV-3", "property")
	v := r33Audit(t, c)
	r33WantBurn(t, v, "INV-3", "INV-3", "''", "no bind can write")
}

// r34RunEvent is one harness_run event for the rail's claimant scan, with the
// property key optionally ABSENT (the exec-bound payload shape).
func r34RunEvent(iid, prop string, hasProp bool) validation.Value {
	data := []validation.KV{
		KV("invariant", validation.VStr(iid)),
		KV("exec", validation.VStr("REPORT-aaaaaaaaaaaa")),
	}
	if hasProp {
		data = append(data, KV("property", validation.VStr(prop)))
	}
	return validation.VObj(
		KV("type", validation.VStr("harness_run")),
		KV("data", validation.VObj(data...)))
}

// TestR34BlankTitleRailClaimants is the claimant-side half of the same
// reading, pinned directly on the rail: a claimant must CARRY a title. An
// event with no property field at all (the exec-bound payload carries none)
// holds no title, so it must never be named as the holder of the blank one —
// a false attribution in the audit's problems is its own lie. An event that
// carries the blank title DOES hold it, exactly as for any other title.
func TestR34BlankTitleRailClaimants(t *testing.T) {
	blank := validation.VObj(
		KV("property", validation.VStr("")),
		KV("exec", validation.VStr("REPORT-aaaaaaaaaaaa")))
	events := []validation.Value{
		r34RunEvent("INV-3", "", true),
		r34RunEvent("INV-4", "", true),
	}
	if msg := reportProofCollisionBurn(events, "INV-4", blank); !strings.Contains(
		msg, "already bound to INV-3") {
		t.Fatalf("a present-but-empty title must collide like any other: %q",
			msg)
	}
	// The same ledger with INV-3's property field ABSENT: INV-3 holds no
	// title, so it cannot be the row that bound "" — the rail reports no
	// collision (INV-4 still burns its own unwritable title).
	events[0] = r34RunEvent("INV-3", "", false)
	if msg := reportProofCollisionBurn(events, "INV-4", blank); msg != "" {
		t.Fatalf("an event with no property field holds no title: %q", msg)
	}
	// Control: the rail reads the title the row under audit names, so a
	// non-blank title must not collide with the blank one.
	events[1] = r34RunEvent("INV-4", "p1", true)
	if msg := reportProofCollisionBurn(events, "INV-4", blank); msg != "" {
		t.Fatalf("a non-blank title must not collide with the blank one: %q",
			msg)
	}
}

// TestR34BlankTitleControlsStayGreen is F1's honest-control half, pinning the
// EDGE of the fix so it cannot over-reach into bind-writable shapes:
//
//   - a whitespace-only title (" ") is NOT empty — the verb's check is
//     `a.property == ""`, so " " passes its door and resolves exactly like
//     any other title; the audit must bless the bind that wrote it;
//   - a non-blank title keeps the r33 behaviour byte for byte: the honest
//     single row is green, and the two-row collision still burns only the
//     later claimant (TestR33ReportDuplicateRowBurns pins that half in the
//     same package).
func TestR34BlankTitleControlsStayGreen(t *testing.T) {
	t.Run("whitespace-only title is bind-writable", func(t *testing.T) {
		c, _, _ := zzR32bCampaign(t, r33Body(" "), " ")
		r34WantGreen(t, r33Audit(t, c), "INV-3")
	})
	t.Run("non-blank title single row stays green", func(t *testing.T) {
		c, _, _ := zzR32bCampaign(t, r33Body("p1"), "p1")
		r34WantGreen(t, r33Audit(t, c), "INV-3")
	})
}

// ---------------------------------------------------------------------------
// F1's adjacent arm: the same shape one field over — a BLANK bound.
// ---------------------------------------------------------------------------

// r34SetSlot replaces iid's stored verification.harness.
func r34SetSlot(t *testing.T, c *state.Campaign, iid string,
	h validation.Value) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	e := validation.ObjAt(reg, iid)
	if e.Kind != validation.Obj {
		t.Fatalf("fixture: no %s in links", iid)
	}
	e.O = validation.SetOrAppend(e.O, "verification",
		validation.VObj(KV("harness", h)))
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}

// r34UnstatedSlot is the slot a bind writes for a report whose property
// rollup is PROVEN with NO stated loop_bound (MapReport: rung proved-bounded,
// summary "autoproved bounded (bound UNSTATED, 1 rules)", bounded_k nil) —
// harnessField drops the null proof sidecar, so the slot renders no k.
func r34UnstatedSlot(sha string) validation.Value {
	return validation.VObj(
		KV("kind", validation.VStr(string(harness.ReportKind))),
		KV("rung", validation.VStr(harness.RungProvedBounded)),
		KV("exec", validation.VStr(harness.ReportExecLabel(sha))),
		KV("bounded_k", validation.VNull()),
		KV("summary", validation.VStr("autoproved bounded (bound UNSTATED, "+
			"1 rules)")),
	)
}

// TestR34BoundUnstatedForgedKBurns is the adjacent arm's pin: the
// pinned report states NO bound, so the display line must render none — but
// harnessBoundK falls back to the SLOT's proof subtree
// (proof.bounds.loop_bound) when bounded_k is not an integer, and
// recheckRegistryEvidence's bound arm only looked at the EVENT's bounded_k
// (blank -> "nothing to compare"). A chain-valid forgery that adds the proof
// subtree to the slot and lands the matching harness_run event therefore
// prints "k=999999" over a report that states no bound.
func TestR34BoundUnstatedForgedKBurns(t *testing.T) {
	body := strings.Replace(r33Body("p1"), `"loop_bound": 4, `, "", 1)
	if body == r33Body("p1") {
		t.Fatal("fixture drift: the mutation did not apply")
	}
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	harnessLinks(t, c, nil)
	sha := zzR32bRegister(t, c, body)
	honest := r34UnstatedSlot(sha)
	r34SetSlot(t, c, "INV-3", honest)
	zzR32bEvent(t, c, "INV-3", honest, sha, "p1")
	if v := r33Audit(t, c); !validation.ObjAt(v, "ok").B {
		t.Fatalf("control: the honest bound-UNSTATED rung must be green: %s",
			validation.CanonCompact(v))
	}
	if line := r33LineFor(r33Audit(t, c), "INV-3"); strings.Contains(line,
		"k=") {
		t.Fatalf("control: the honest line must render no k: %q", line)
	}
	// The forgery: the slot grows the proof subtree, the event is re-landed
	// with the digest of those very bytes (zzR32bEvent recomputes
	// proof_sha256), so every slot<->ledger backstop still agrees.
	forged := validation.VObj(
		KV("kind", validation.VStr(string(harness.ReportKind))),
		KV("rung", validation.VStr(harness.RungProvedBounded)),
		KV("exec", validation.VStr(harness.ReportExecLabel(sha))),
		KV("bounded_k", validation.VNull()),
		KV("summary", validation.VStr("autoproved bounded (bound UNSTATED, "+
			"1 rules)")),
		KV("proof", validation.VObj(KV("bounds", validation.VObj(
			KV("loop_bound", validation.VInt(999999)))))),
	)
	r34SetSlot(t, c, "INV-3", forged)
	zzR32bEvent(t, c, "INV-3", forged, sha, "p1")

	v := r33Audit(t, c)
	if validation.ObjAt(v, "ok").B {
		t.Fatalf("the audit blesses a bound the pinned report never "+
			"stated: %s", validation.CanonCompact(v))
	}
	r33WantBurn(t, v, "INV-3", "INV-3", "999999", "states no bound")
}
