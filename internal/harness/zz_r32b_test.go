package harness

// zz_r32b_test.go — r32b F1 at the unit level: harness.DecideReport is the
// ONE autoprove decision the bind and audit both run, so its gate table is
// pinned here directly, and harness.ReportProperty's exact-only lookup plus
// ReportSuspects' fail-closed shapes are pinned next to it.
//
// These tests are the pin on the NEW API (they could not fail before the
// change — the function did not exist); the "failing before the change"
// evidence for r32b lives in internal/cli/zz_r32b_test.go (bind vs audit,
// end to end) and internal/audit/sections/zz_r32b_test.go (section 11 over a
// forged pinned copy).

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// r32bRep builds a report and applies the caller's overrides in place (an
// override REPLACES the key the honest body carries).
func r32bRep(prop string, over ...validation.KV) validation.Value {
	rep := validation.VObj(
		validation.KV{K: "schema_version", V: validation.VStr("1.0")},
		validation.KV{K: "published", V: validation.VBool(true)},
		validation.KV{K: "publish_problems", V: validation.VArr()},
		validation.KV{K: "review_findings", V: validation.VArr()},
		validation.KV{K: "flags", V: validation.VObj(
			validation.KV{K: "loop_bound", V: validation.VInt(4)})},
		validation.KV{K: "property_outcomes", V: validation.VObj(
			validation.KV{K: prop, V: validation.VObj(
				validation.KV{K: "outcome", V: validation.VStr("PROVEN")},
				validation.KV{K: "per_rule", V: validation.VObj(
					validation.KV{K: "inv_1",
						V: validation.VStr("PROVEN")})})})},
	)
	for _, kv := range over {
		rep.O = validation.SetOrAppend(rep.O, kv.K, kv.V)
	}
	return rep
}

// TestR32bDecideReportGateTable pins each of the five gates plus the two
// supporting refusals (the property lookup and the typed bound), in the
// bind's own order, with the bind's own sentence.
func TestR32bDecideReportGateTable(t *testing.T) {
	suspect := validation.VObj(
		validation.KV{K: "property", V: validation.VStr("p1")},
		validation.KV{K: "verdict", V: validation.VStr("SUSPECT")},
		validation.KV{K: "reason", V: validation.VStr("vacuous rule")})
	tests := []struct {
		name    string
		rep     validation.Value
		prop    string
		gate    ReportGate
		refusal string
	}{{
		"honest report maps",
		r32bRep("p1"), "p1", GateNone, "",
	}, {
		"a non-suspect finding is not a flag",
		r32bRep("p1", validation.KV{K: "review_findings",
			V: validation.VArr(validation.VObj(
				validation.KV{K: "property", V: validation.VStr("p1")},
				validation.KV{K: "verdict", V: validation.VStr("ok")}))}),
		"p1", GateNone, "",
	}, {
		"published false",
		r32bRep("p1", validation.KV{K: "published",
			V: validation.VBool(false)}),
		"p1", GatePublished, "did NOT publish",
	}, {
		"the veto list is read even with published true",
		r32bRep("p1", validation.KV{K: "publish_problems",
			V: validation.VArr(validation.VStr("rule inv_1 unverifiable"))}),
		"p1", GatePublishProblems, "internally",
	}, {
		"the veto list must be a list",
		r32bRep("p1", validation.KV{K: "publish_problems",
			V: validation.VStr("nope")}),
		"p1", GatePublishProblemsShape, "malformed publish_problems",
	}, {
		"a crashed review is never a cleared check",
		r32bRep("p1", validation.KV{K: "review_error",
			V: validation.VStr("review model call failed: boom")}),
		"p1", GateReviewError, "NEVER RAN",
	}, {
		"the findings list must be a list",
		r32bRep("p1", validation.KV{K: "review_findings",
			V: validation.VNull()}),
		"p1", GateReviewFindingsShape, "malformed review_findings",
	}, {
		"SUSPECT is the gate",
		r32bRep("p1", validation.KV{K: "review_findings",
			V: validation.VArr(suspect)}),
		"p1", GateSuspect, "SUSPECT",
	}, {
		"the same word padded and shouted",
		r32bRep("p1", validation.KV{K: "review_findings",
			V: validation.VArr(validation.VObj(
				validation.KV{K: "property", V: validation.VStr("p1")},
				validation.KV{K: "verdict",
					V: validation.VStr(" suspect ")},
				validation.KV{K: "reason",
					V: validation.VStr("padded")}))}),
		"p1", GateSuspect, "padded",
	}, {
		"property_outcomes is required",
		r32bRep("p1", validation.KV{K: "property_outcomes",
			V: validation.VNull()}),
		"p1", GatePropertyOutcomes, "no property_outcomes",
	}, {
		"the property lookup is EXACT (fold-equal pins nothing)",
		r32bRep("p1"), "P1", GateProperty, "exact-match only",
	}, {
		"a degenerate bound is not twin output",
		r32bRep("p1", validation.KV{K: "flags", V: validation.VObj(
			validation.KV{K: "loop_bound", V: validation.VInt(0)})}),
		"p1", GateLoopBound, "degenerate bounds",
	}, {
		"a float bound is truncation",
		r32bRep("p1", validation.KV{K: "flags", V: validation.VObj(
			validation.KV{K: "loop_bound", V: validation.VFloat(4.5)})}),
		"p1", GateLoopBound, "not an integer",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := DecideReport(tc.rep, tc.prop)
			if dec.Gate != tc.gate {
				t.Fatalf("gate = %q, want %q (refusal %q)", dec.Gate,
					tc.gate, dec.Refusal)
			}
			if tc.refusal == "" {
				if dec.Refusal != "" {
					t.Fatalf("an honest report owes no refusal: %q",
						dec.Refusal)
				}
				return
			}
			if !strings.Contains(dec.Refusal, tc.refusal) {
				t.Fatalf("refusal %q must name %q", dec.Refusal,
					tc.refusal)
			}
			if !strings.HasSuffix(dec.Refusal, "\n") {
				t.Fatalf("a refusal is a printed sentence: %q", dec.Refusal)
			}
		})
	}
}

// TestR32bDecideReportMapsTheRollup pins the honest half of the decision:
// the mapping itself is MapReport's, byte for byte.
func TestR32bDecideReportMapsTheRollup(t *testing.T) {
	dec := DecideReport(r32bRep("p1"), "p1")
	wantRung, wantSum, wantBK := MapReport("PROVEN", validation.VObj(
		validation.KV{K: "inv_1", V: validation.VStr("PROVEN")}), 4, true)
	if dec.Gate != GateNone || dec.Rung != wantRung ||
		dec.Summary != wantSum || dec.BoundedK == nil || wantBK == nil ||
		*dec.BoundedK != *wantBK {
		t.Fatalf("decision = %+v, want rung %q summary %q k %v", dec,
			wantRung, wantSum, *wantBK)
	}
	if dec.Outcome != "PROVEN" {
		t.Fatalf("outcome = %q", dec.Outcome)
	}
}

// TestR32bReportPropertyIsExactOnly is F1's lookup half at the unit level:
// the audit's old fold fallback is gone, so a fold-equal spelling resolves
// to nothing — exactly as cli.fieldOf resolved it for the bind.
func TestR32bReportPropertyIsExactOnly(t *testing.T) {
	rep := r32bRep("p1")
	if _, ok := ReportProperty(rep, "p1"); !ok {
		t.Fatal("the exact key must resolve")
	}
	for _, name := range []string{"P1", " p1", "p1 ", "p 1", "P 1"} {
		if _, ok := ReportProperty(rep, name); ok {
			t.Fatalf("%q must not resolve against the key 'p1' (the bind "+
				"is exact-match only)", name)
		}
	}
}

// TestR32bSuspectsFailClosed pins ReportSuspects' fail-closed shapes: an
// unparseable finding counts against EVERY property, and a suspect verdict
// with no property attribution does too.
func TestR32bSuspectsFailClosed(t *testing.T) {
	bare := r32bRep("p1", validation.KV{K: "review_findings",
		V: validation.VArr(validation.VStr("the whole review was a mess"))})
	if got := ReportSuspects(bare, "p1"); !strings.Contains(got,
		"malformed review finding") {
		t.Fatalf("a non-object finding must count against every property: %q",
			got)
	}
	unattached := r32bRep("p1", validation.KV{K: "review_findings",
		V: validation.VArr(validation.VObj(
			validation.KV{K: "verdict", V: validation.VStr("suspect")},
			validation.KV{K: "reason",
				V: validation.VStr("which property? all of them")}))})
	if got := ReportSuspects(unattached, "p1"); !strings.Contains(got,
		"counted against every property") {
		t.Fatalf("an unattributed suspect finding must count against every "+
			"property: %q", got)
	}
	if got := ReportSuspects(r32bRep("p1"), "p1"); got != "" {
		t.Fatalf("a clean review flags nothing: %q", got)
	}
}

// TestR32bRefusalsAreTheBindsHistoricalBytes pins the refusal sentences the
// bind printed BEFORE the extraction: r32b F1 moved the five gates (and the
// property lookup and the bound read) into harness without moving a byte —
// cli.verifyAutoprove prints "verify --autoprove: " + Refusal verbatim, and
// each string below is the sentence that was inline in cmd_verify_autoprove
// before this round. (Kind renders as its byte, e.g. 115 = Str, 110 = Null,
// because validation.Kind is a byte type with no String method — the old
// code's %v did exactly the same. The ONE deliberate divergence is
// documented on DecideReport: a NON-BOOL `published` now reads through
// validation.PyTruthy, so an out-of-int64 zero reads as not-published.)
func TestR32bRefusalsAreTheBindsHistoricalBytes(t *testing.T) {
	tests := []struct {
		name string
		rep  validation.Value
		prop string
		want string
	}{{
		"publish_problems shape",
		r32bRep("p1", validation.KV{K: "publish_problems",
			V: validation.VStr("nope")}),
		"p1",
		"malformed publish_problems (kind 115, contract: array) — the " +
			"veto list is machine-authored; refusing to read a broken " +
			"contract\n",
	}, {
		"publish_problems non-empty while claiming published",
		r32bRep("p1", validation.KV{K: "publish_problems",
			V: validation.VArr(validation.VStr("rule inv_1 unverifiable"))}),
		"p1",
		"the report carries publish_problems (rule inv_1 unverifiable) " +
			"while claiming published — internally contradictory; nothing " +
			"binds\n",
	}, {
		"publish_problems non-empty and unpublished",
		r32bRep("p1",
			validation.KV{K: "published", V: validation.VBool(false)},
			validation.KV{K: "publish_problems", V: validation.VArr(
				validation.VStr("rule inv_1 unverifiable"))}),
		"p1",
		"the report carries publish_problems (rule inv_1 unverifiable) — " +
			"the run is unpublished; nothing binds\n",
	}, {
		"unpublished with no problems",
		r32bRep("p1", validation.KV{K: "published",
			V: validation.VBool(false)}),
		"p1",
		"the prover did NOT publish this run — nothing is blessed " +
			"(problems: -)\n",
	}, {
		"review_error",
		r32bRep("p1", validation.KV{K: "review_error",
			V: validation.VStr("boom")}),
		"p1",
		"the independent review NEVER RAN (boom) — PROVEN binds without " +
			"it only by inattention; refusing\n",
	}, {
		"review_findings shape",
		r32bRep("p1", validation.KV{K: "review_findings",
			V: validation.VNull()}),
		"p1",
		"malformed review_findings (kind 110, contract: array) — the gate " +
			"reads the review's output; a broken one is never empty enough " +
			"to pass\n",
	}, {
		"SUSPECT",
		r32bRep("p1", validation.KV{K: "review_findings",
			V: validation.VArr(validation.VObj(
				validation.KV{K: "property", V: validation.VStr("p1")},
				validation.KV{K: "verdict", V: validation.VStr("suspect")},
				validation.KV{K: "reason",
					V: validation.VStr("vacuous rule")}))}),
		"p1",
		"the independent review flagged property p1 as SUSPECT — vacuous " +
			"rule — a PROVEN verdict next to a suspect review is the most " +
			"expensive state there is; the rung is refused, fix the rule " +
			"or waive with reason\n",
	}, {
		"property not in the run (exact-match only)",
		r32bRep("p1"),
		"P1",
		"property 'P1' is not in this run (the prover attempted: p1) — " +
			"exact-match only\n",
	}, {
		"degenerate bound",
		r32bRep("p1", validation.KV{K: "flags", V: validation.VObj(
			validation.KV{K: "loop_bound", V: validation.VInt(0)})}),
		"p1",
		"flags.loop_bound is 0 — the twin refuses degenerate bounds (<1; " +
			"a k=0 'proof' checks only the initial state); this report is " +
			"not a twin output and will not bind\n",
	}, {
		"property_outcomes missing",
		r32bRep("p1", validation.KV{K: "property_outcomes",
			V: validation.VNull()}),
		"p1",
		"report carries no property_outcomes map — contract broken\n",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecideReport(tc.rep, tc.prop).Refusal; got != tc.want {
				t.Fatalf("refusal = %q, want %q", got, tc.want)
			}
		})
	}
}
