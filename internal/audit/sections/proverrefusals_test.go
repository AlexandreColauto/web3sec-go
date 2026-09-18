package sections

// Task 5 (L-defer) render pins: invariant_verification's harness_runs array
// gains ONE derived line after the per-invariant harness lines — the L3
// refusal histogram, computed from the campaign's stored
// verification.harness records (kind minicertora, rung inconclusive).
// Presence-gated: a campaign that stores no eligible record renders the
// historical bytes exactly (halmos-only, and minicertora without refusals),
// and the per-invariant lines themselves never move.

import (
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// refusalRow is one seeded registry entry: an invariant id and the
// verification.harness object to land on it.
type refusalRow struct {
	id string
	h  validation.Value
}

// seedRefusalLinks seeds the rows' invariants and lands each harness object
// — the harnessLinks path, for an arbitrary id set (a histogram row needs up
// to five invariants).
func seedRefusalLinks(t *testing.T, c *state.Campaign, rows []refusalRow) {
	t.Helper()
	invs := make([]validation.Value, 0, len(rows))
	for _, r := range rows {
		invs = append(invs, validation.VObj(
			KV("id", validation.VStr(r.id)),
			KV("statement", validation.VStr("refusal row "+r.id)),
		))
	}
	if _, err := invariants.SeedFromModel(c,
		validation.VObj(KV("invariants", validation.VArr(invs...)))); err != nil {
		t.Fatal(err)
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	for _, r := range rows {
		e := validation.ObjAt(reg, r.id)
		e.O = validation.SetOrAppend(e.O, "verification",
			validation.VObj(KV("harness", r.h)))
		reg.O = validation.SetOrAppend(reg.O, r.id, e)
	}
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		backEvent(t, c, r.id, r.h) // r21 F7: slots must be event-backed
	}
}

// proofReason is the L-core proof sidecar carrying the stored reason code
// (harness.mcProof always writes the key; the fallback rows spell the
// sidecar-less shape by omitting it entirely).
func proofReason(code string) validation.Value {
	return validation.VObj(KV("reason", validation.VStr(code)))
}

// mcRefusal is a stored rule-level refusal: kind minicertora, rung
// inconclusive, the mapper's "inconclusive (reason: details)" summary and
// the sidecar carrying the reason code.
func mcRefusal(code, details string) validation.Value {
	return harnessProofObj("minicertora", "inconclusive", "EXEC-9",
		validation.VNull(),
		"inconclusive ("+code+": "+details+")", proofReason(code))
}

// sidecarlessRefusal is the same summary WITHOUT a proof sidecar: the
// shape a stored record takes when only the summary can name the class (a
// minicertora record whose sidecar never landed, e.g. the abort envelope).
func sidecarlessRefusal(summary string) validation.Value {
	return harnessObj("minicertora", "inconclusive", "EXEC-9",
		validation.VNull(), summary)
}

// nextTail is a mapped refusal's per-invariant tail — verbatim from the
// production disposition table, so the row's bytes pin the FULL array
// (lines plus histogram) without transcribing the advice prose. The line's
// format is byte-pinned by TestHarnessRunLineDispositions; these rows pin
// what follows it.
func nextTail(code string) string {
	class, advice, _ := harness.Disposition("inconclusive (" + code + ": x)")
	return " | next: " + advice + " (" + class + ")"
}

// TestInvariantVerificationRefusalHistogram pins the derived line byte for
// byte, the array position it takes (last, after every per-invariant line),
// and the presence gate (no eligible record ⇒ no line at all). The table's
// want arrays are the COMPLETE harness_runs value.
func TestInvariantVerificationRefusalHistogram(t *testing.T) {
	tests := []struct {
		name string
		rows []refusalRow
		want []string
	}{{
		// The architecture's own example shape: two packed-storage
		// rejections (the corpus's "rejected-feature" code, details
		// naming the packed slot) and one bound escalation.
		name: "2 packed-storage + 1 escalate-bound campaign",
		rows: []refusalRow{
			{"INV-1", mcRefusal("rejected-feature", "ln:Packed.b")},
			{"INV-2", mcRefusal("rejected-feature", "ln:Escrow.b")},
			{"INV-3", mcRefusal("loop-bound-may-be-exceeded", "8")},
		},
		want: []string{
			"INV-1: inconclusive (minicertora, EXEC-9)" +
				nextTail("rejected-feature"),
			"INV-2: inconclusive (minicertora, EXEC-9)" +
				nextTail("rejected-feature"),
			"INV-3: inconclusive (minicertora, EXEC-9)" +
				nextTail("loop-bound-may-be-exceeded"),
			"prover refusals (minicertora): 3 — honest-refusal:2, " +
				"escalate-bound:1; top reasons: rejected-feature×2, " +
				"loop-bound-may-be-exceeded×1",
		},
	}, {
		// The rule-less abort envelope (no verdict line ⇒ no sidecar):
		// unclassifiable, so it buckets as "unmapped" — counted, not
		// dropped, and named as such.
		name: "rule-less abort refusals bucket as unmapped",
		rows: []refusalRow{
			{"INV-1", sidecarlessRefusal(
				"aborted: rejected-feature: packed-storage:Packed.b")},
			{"INV-2", sidecarlessRefusal(
				"aborted: rejected-feature: packed-storage:Packed.b")},
		},
		want: []string{
			"INV-1: inconclusive (minicertora, EXEC-9)",
			"INV-2: inconclusive (minicertora, EXEC-9)",
			"prover refusals (minicertora): 2 — unmapped:2; " +
				"top reasons: unmapped×2",
		},
	}, {
		// Mixed: the same summary with and without a stored code. The
		// coded record names its code; the sidecar-less one falls back
		// to the summary's class, and the two reason buckets tie at 1
		// (code-asc decides the order).
		name: "mixed proof.reason-absent fallback",
		rows: []refusalRow{
			{"INV-1", mcRefusal("path-limit-reached", "256")},
			{"INV-2", sidecarlessRefusal(
				"inconclusive (path-limit-reached: 256)")},
		},
		want: []string{
			"INV-1: inconclusive (minicertora, EXEC-9)" +
				nextTail("path-limit-reached"),
			"INV-2: inconclusive (minicertora, EXEC-9)" +
				nextTail("path-limit-reached"),
			"prover refusals (minicertora): 2 — escalate-flag:2; " +
				"top reasons: escalate-flag×1, path-limit-reached×1",
		},
	}, {
		// Both columns tie at 2, and the two orderings disagree:
		// classes ascend spec-rewrite < tool-error, codes ascend
		// tool-error < vacuous-rule. A single sort feeding both
		// columns cannot render this line.
		name: "ordering tie-break, each column independently",
		rows: []refusalRow{
			{"INV-1", mcRefusal("vacuous-rule", "b1")},
			{"INV-2", mcRefusal("vacuous-rule", "b2")},
			{"INV-3", mcRefusal("tool-error", "solver died")},
			{"INV-4", mcRefusal("tool-error", "tool crashed")},
		},
		want: []string{
			"INV-1: inconclusive (minicertora, EXEC-9)" +
				nextTail("vacuous-rule"),
			"INV-2: inconclusive (minicertora, EXEC-9)" +
				nextTail("vacuous-rule"),
			"INV-3: inconclusive (minicertora, EXEC-9)" +
				nextTail("tool-error"),
			"INV-4: inconclusive (minicertora, EXEC-9)" +
				nextTail("tool-error"),
			"prover refusals (minicertora): 4 — spec-rewrite:2, " +
				"tool-error:2; top reasons: tool-error×2, vacuous-rule×2",
		},
	}, {
		// Five refusals, four reasons: count-desc puts the pair
		// first, the three singletons ascend by code, and the cap
		// drops the fourth reason (solver-timeout) while the class
		// column stays complete and sums to the total.
		name: "top reasons capped at three",
		rows: []refusalRow{
			{"INV-1", mcRefusal("loop-bound-may-be-exceeded", "4")},
			{"INV-2", mcRefusal("loop-bound-may-be-exceeded", "8")},
			{"INV-3", mcRefusal("path-limit-reached", "256")},
			{"INV-4", mcRefusal("rejected-feature", "ln:Packed.b")},
			{"INV-5", mcRefusal("solver-timeout", "30000ms")},
		},
		want: []string{
			"INV-1: inconclusive (minicertora, EXEC-9)" +
				nextTail("loop-bound-may-be-exceeded"),
			"INV-2: inconclusive (minicertora, EXEC-9)" +
				nextTail("loop-bound-may-be-exceeded"),
			"INV-3: inconclusive (minicertora, EXEC-9)" +
				nextTail("path-limit-reached"),
			"INV-4: inconclusive (minicertora, EXEC-9)" +
				nextTail("rejected-feature"),
			"INV-5: inconclusive (minicertora, EXEC-9)" +
				nextTail("solver-timeout"),
			"prover refusals (minicertora): 5 — escalate-bound:2, " +
				"escalate-flag:1, escalate-solver:1, honest-refusal:1; " +
				"top reasons: loop-bound-may-be-exceeded×2, " +
				"path-limit-reached×1, rejected-feature×1",
		},
	}, {
		// A code outside §L3's closed set: still a refusal, bucketed
		// as "unmapped" rather than printed as vocabulary the table
		// does not know.
		name: "unknown reason code buckets as unmapped",
		rows: []refusalRow{
			{"INV-1", mcRefusal("quark-tunneling", "x")},
		},
		want: []string{
			"INV-1: inconclusive (minicertora, EXEC-9)" +
				nextTail("quark-tunneling"),
			"prover refusals (minicertora): 1 — unmapped:1; " +
				"top reasons: unmapped×1",
		},
	}, {
		// Presence gate, kind half: a halmos INCONCLUSIVE rung is
		// exactly the shape the histogram must ignore; the halmos and
		// forge-fuzz lines keep their historical bytes.
		name: "halmos-only campaign emits no refusal line",
		rows: []refusalRow{
			{"INV-1", harnessObj("halmos", "inconclusive", "EXEC-3",
				validation.VNull(), "inconclusive (exit output unmapped)")},
			{"INV-2", harnessObj("forge-fuzz", "counterexample", "EXEC-9",
				validation.VNull(), "counterexample: fuzz test seed: 5")},
		},
		want: []string{
			"INV-1: inconclusive (halmos, EXEC-3)",
			"INV-2: counterexample (forge-fuzz, EXEC-9)",
		},
	}, {
		// Presence gate, rung half: minicertora records with no
		// refusal contribute nothing (the tally is empty, so the key
		// keeps its historical two lines).
		name: "minicertora campaign without refusals emits no line",
		rows: []refusalRow{
			{"INV-1", harnessObj("minicertora", "proved-bounded", "EXEC-10",
				validation.VInt(4), "proved bounded (k=4)")},
			{"INV-2", harnessObj("minicertora", "counterexample", "EXEC-11",
				validation.VNull(), "counterexample: total >= before")},
		},
		want: []string{
			"INV-1: PROVEN-BOUNDED (minicertora, k=4, EXEC-10)",
			"INV-2: counterexample (minicertora, EXEC-11)",
		},
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := state.Init(t.TempDir(), "Acme Program",
				state.InitOpts{})
			if err != nil {
				t.Fatal(err)
			}
			seedRefusalLinks(t, c, tc.rows)
			v, err := InvariantVerification(c)
			if err != nil {
				t.Fatal(err)
			}
			runs := validation.ObjAt(v, "harness_runs")
			if runs.Kind != validation.Arr {
				t.Fatalf("harness_runs = %s, want %d lines",
					validation.CanonCompact(runs), len(tc.want))
			}
			got := make([]string, 0, len(runs.A))
			for _, item := range runs.A {
				got = append(got, item.S)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("harness_runs = %q, want %q", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i],
						tc.want[i])
				}
			}
			// The histogram is informational: it never moves the
			// verdict halves.
			if !validation.ObjAt(v, "ok").B {
				t.Errorf("ok must stay true: %s",
					validation.CanonCompact(v))
			}
		})
	}
}

// TestInvariantVerificationRefusalHistogramAbsentWithoutHarness pins the
// golden contract for the new line: an invariant registry with no
// verification.harness anywhere renders the historical key set — no
// harness_runs key, hence no histogram.
func TestInvariantVerificationRefusalHistogramAbsentWithoutHarness(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	seedRefusalLinks(t, c, []refusalRow{
		{"INV-1", validation.VNull()},
	})
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if h := validation.ObjAt(v, "harness_runs"); h.Kind != validation.Null {
		t.Fatalf("harness_runs = %s, want the key omitted",
			validation.CanonCompact(h))
	}
}
