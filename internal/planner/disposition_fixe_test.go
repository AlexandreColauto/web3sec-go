package planner

// disposition_fixe_test.go — round-3 chief item 5, FIX-E: the --passes
// plausibility floor has no bypass and no silent route. (1) the quoted-string
// arm of the literal alternation is held to the same junk lexicon as a bare
// value ("TBD" under quotes is still TBD), and an honest quoted literal that
// merely CONTAINS a junk word stays legal; (2) a --passes supplied on a
// non-sentinel route is validated through the SAME floor — never recorded
// verbatim, never silently dropped by closePriority's length guard.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestSentinelPassesQuotedJunkRefused pins FIX-E problem 1: the quoted arms
// of passesLiteralRe do not admit the junk lexicon. Every refused value must
// name both legal shapes; the honest quoted literal that contains a junk
// word, and every bare junk form, keep their existing verdicts.
func TestSentinelPassesQuotedJunkRefused(t *testing.T) {
	camp, _, rowID := sentinelDispositionFixture(t)

	// (a) quoted junk: refused with both legal shapes named
	for _, junk := range []string{`"TBD"`, `"zzz"`, `'n/a'`, `"NA"`,
		`'none'`, `"unknown"`, `'whatever'`, `"asdf"`, `'xxx'`, `"foo"`,
		`'bar'`, `"baz"`} {
		_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
			&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &junk})
		if err == nil || !strings.Contains(err.Error(),
			"is not a plausible value for the check") {
			t.Fatalf("quoted junk --passes %q must be refused: %v", junk, err)
		}
		if !strings.Contains(err.Error(), "row's own surface entry") ||
			!strings.Contains(err.Error(), "concrete literal") {
			t.Errorf("refusal does not name both legal shapes for %q:\n%v",
				junk, err)
		}
		// negative control: the refusal is a decision that did not happen
		prio := storedPriority(t, camp, rowID)
		if got := validation.ObjStr(prio, "status"); got != "open" {
			t.Fatalf("quoted junk %q refusal changed the status to %q",
				junk, got)
		}
		if validation.ObjAt(prio, "passes").Kind != validation.Null {
			t.Fatalf("quoted junk %q refusal recorded passes", junk)
		}
	}

	// (b) the honest quoted literal that CONTAINS a junk word stays legal —
	// the lexicon is whole-value, never a substring scan. morph §6.1/§7.1:
	// the enforcement-timing row owes the interim pricing too, so it is
	// priced here and the floor under test stays the only thing deciding.
	honest := `"3 days of unresolved withdrawals"`
	fixInterim := "until finalizeBatch asserts prev:state, commitBatch " +
		"accepts a stale root"
	_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &honest,
			Interim: &fixInterim})
	if err != nil {
		t.Fatalf("honest quoted literal refused: %v", err)
	}
	if got := validation.ObjStr(storedPriority(t, camp, rowID), "passes"); got != honest {
		t.Errorf("passes = %q, want %q", got, honest)
	}
}

// TestPassesAlwaysValidated pins FIX-E problem 2: whenever --passes is
// supplied, the same plausibility floor applies — on a NON-sentinel probe
// row, on a plain (non-probe) priority, and on a non-closing status. Junk is
// refused naming the legal shapes; a short value is a refusal naming the
// >= 3 floor, not closePriority's silent drop; an honest value passes and is
// recorded.
func TestPassesAlwaysValidated(t *testing.T) {
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "fixe-passes")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	// a plain (non-probe) priority: no sentinel gate covers it — the floor
	// must still apply
	plain := validation.VObj(kv("id", validation.VStr("Q-900")),
		kv("question", validation.VStr(
			"the drain-capable role is a single multisig, not reachable")),
		kv("risk", validation.VFloat(0.5)),
		kv("trajectories", validation.VArr(validation.VStr("economic"))),
		kv("status", validation.VStr("open")))
	plan.O = validation.SetOrAppend(plan.O, "priorities", validation.VArr(
		append(listOf(plan, "priorities"), plain)...))
	if _, err := SavePlan(camp, deepCopy(t, plan)); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	reason := "the drain-capable role is a single multisig, not reachable"

	// (a) junk --passes on the plain priority: refused, both shapes named
	junk := "TBD"
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, PassesValue: &junk})
	if err == nil || !strings.Contains(err.Error(),
		"is not a plausible value for the check") {
		t.Fatalf("junk --passes on a plain priority must be refused: %v", err)
	}
	if !strings.Contains(err.Error(), "row's own surface entry") ||
		!strings.Contains(err.Error(), "concrete literal") {
		t.Errorf("refusal does not name both legal shapes:\n%v", err)
	}

	// (b) a short value: REFUSED naming the floor, never silently dropped
	short := "no"
	_, err = MarkAnswered(camp, deepCopy(t, plan), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, PassesValue: &short})
	if err == nil || !strings.Contains(err.Error(), "3-character floor") {
		t.Fatalf("short --passes must be refused with the floor named: %v",
			err)
	}
	// negative control: the refusal is a decision that did not happen
	planAfter, err := LoadPlanReadonly(camp)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range listOf(planAfter, "priorities") {
		if validation.ObjStr(q, "id") == "Q-900" {
			if validation.ObjAt(q, "passes").Kind != validation.Null {
				t.Fatalf("short --passes was recorded as %q",
					validation.ObjStr(q, "passes"))
			}
			if got := validation.ObjStr(q, "status"); got != "open" {
				t.Fatalf("refusal changed the status to %q", got)
			}
		}
	}

	// (c) the same on a NON-sentinel probe row (the surface's rows carry no
	// own_form): the floor applies there too
	rowID := "81dfad6492"
	_, _, err = plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &junk})
	if err == nil || !strings.Contains(err.Error(),
		"is not a plausible value for the check") {
		t.Fatalf("junk --passes on a non-sentinel probe row must be "+
			"refused: %v", err)
	}

	// (d) an honest literal passes on the plain priority and is recorded
	literal := "0xdeadbeef"
	plan3, err := MarkAnswered(camp, deepCopy(t, plan), "Q-900", "answered",
		AnsweredOpts{Reason: &reason, PassesValue: &literal})
	if err != nil {
		t.Fatalf("honest --passes must pass: %v", err)
	}
	var got string
	for _, q := range listOf(plan3, "priorities") {
		if validation.ObjStr(q, "id") == "Q-900" {
			got = validation.ObjStr(q, "passes")
		}
	}
	if got != literal {
		t.Errorf("passes = %q, want %q", got, literal)
	}

	// (e) always means always: a REOPEN with junk --passes is refused too
	_, err = MarkAnswered(camp, plan, "Q-900", "open",
		AnsweredOpts{PassesValue: &junk})
	if err == nil || !strings.Contains(err.Error(),
		"is not a plausible value for the check") {
		t.Fatalf("junk --passes must be refused on a reopen: %v", err)
	}
}
