package harness

import "testing"

func TestDispositionTable(t *testing.T) {
	tests := []struct {
		name    string
		summary string
		class   string
		advice  string // "" means: assert non-empty only
		ok      bool
	}{
		{"loop bound", "inconclusive (loop-bound-may-be-exceeded: loop 4 exceeded on path 11)", EscalateBound,
			"re-run the same scaffold at --loop-bound 8, then 16, ceiling 32", true},
		{"path cap", "inconclusive (path-limit-reached: 2000 paths)", EscalateFlag, "", true},
		{"solver timeout", "inconclusive (solver-timeout: VC 12 after 30000ms)", EscalateSolver, "", true},
		{"vacuous rule", "inconclusive (vacuous-rule: pre never satisfiable)", SpecRewrite, "", true},
		{"vacuous block", "inconclusive (vacuous-block: unreachable branch body)", SpecRewrite, "", true},
		{"malformed spec", "inconclusive (malformed-spec: expected ';')", SpecRewrite, "", true},
		{"unsupported feature", "inconclusive (unsupported-feature: CREATE2 at C.f)", HonestRefusal, "", true},
		{"multi-call class", "inconclusive (multi-call-ambiguous-call-site: two calls)", HonestRefusal, "", true},
		{"tool error", "inconclusive (tool-error: bundle path /tmp/x)", ToolError, "", true},
		{"model bug", "inconclusive (unresolved-phi-source: line 44)", ModelBug, "", true},
		{"solver disagreement", "inconclusive (solver-disagreement: z3 vs cvc5)", ModelBug, "", true},
		{"unknown code", "inconclusive (something-new: details)", "unmapped",
			"review the spec and the tool version; the refusal names no known disposition", true},
		{"floor no output", "inconclusive (exit output unmapped)", "", "", false},
		{"floor not jsonl", "inconclusive (output is not JSONL)", "", "", false},
		{"floor aborted", "aborted: disk full: detail", "", "", false},
		// H1 belt-and-braces: the abort floor with the inconclusive wrapper
		// on (the mapper does not build this today) must still be plumbing.
		{"floor aborted wrapped", "inconclusive (aborted: tool-error: spec file unreadable)", "", "", false},
		{"floor contradiction", "inconclusive (report-contradiction: exit 0 with verdict PROVEN)", "", "", false},
		// The CLI appends the binding decoration " (unbound: …)" to
		// whatever the mapper stored (cmd_verify_harness.harnessMapBound).
		// A decorated FLOOR must still floor: the decoration's own ": "
		// must not be mistaken for a reason separator (that bug rendered
		// a bogus "unmapped" advice on a plumbing floor).
		{"decorated floor", "inconclusive (exit output unmapped) (unbound: harness file hash not recorded)", "", "", false},
		// …and a decorated MAPPED reason keeps its real class and advice.
		{"decorated mapped reason", "inconclusive (loop-bound-may-be-exceeded: x) (unbound: harness file hash not recorded)", EscalateBound,
			"re-run the same scaffold at --loop-bound 8, then 16, ceiling 32", true},
		{"floor no line", "inconclusive (no verdict line for rule inv_1)", "", "", false},
		{"floor duplicate", "inconclusive (duplicate verdict lines for rule)", "", "", false},
		// M1: the plumbing floors are matched on INNER TEXT before the
		// ": " separator, so a rule name that itself contains ": " can
		// no longer masquerade as a reason code ("no verdict line for
		// rule a: b" used to parse reason "no verdict line for rule a").
		{"floor no line with colon in rule name", "inconclusive (no verdict line for rule a: b)", "", "", false},
		// The named runtime floor: a killed or timed-out minicertora run
		// never produced a verdict, so it disposes to escalate-runtime
		// (one more budgeted EXEC with a larger wall-clock), not to a
		// spec class and not to plumbing. Both wave-3 shapes classify.
		{"runtime floor bare", "inconclusive (no clean completion)", EscalateRuntime,
			"the run never completed — re-run with a larger --timeout-ms or a longer exec wall-clock; a killed or timed-out run maps no verdict", true},
		{"runtime floor with bound", "inconclusive (no clean completion; loop bound was 4)", EscalateRuntime, "", true},
		// …and the binding decoration does not change either shape.
		{"decorated runtime floor bare", "inconclusive (no clean completion) (unbound: harness file hash not recorded)", EscalateRuntime, "", true},
		{"decorated runtime floor with bound", "inconclusive (no clean completion; loop bound was 8) (unbound: harness file hash not recorded)", EscalateRuntime, "", true},
		{"not inconclusive", "proved bounded (k=4)", "", "", false},
		{"counterexample excerpt", "counterexample: total >= before [unconfirmed: crosses a havoc'd call]", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			class, advice, ok := Disposition(tc.summary)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (class %q)", ok, tc.ok, class)
			}
			if !tc.ok {
				return
			}
			if class != tc.class {
				t.Errorf("class = %q, want %q", class, tc.class)
			}
			if tc.advice != "" && advice != tc.advice {
				t.Errorf("advice = %q, want %q", advice, tc.advice)
			}
			if tc.advice == "" && advice == "" {
				t.Errorf("advice empty for class %q", class)
			}
		})
	}
}

func TestDispositionCoversClosedSet(t *testing.T) {
	// every one of the 25 codes must classify to its §L3 class; one row per code.
	codes := map[string]string{
		"loop-bound-may-be-exceeded": EscalateBound, "path-limit-reached": EscalateFlag,
		"solver-timeout": EscalateSolver, "vacuous-rule": SpecRewrite, "vacuous-block": SpecRewrite,
		"malformed-spec":      SpecRewrite,
		"unsupported-feature": HonestRefusal, "unsupported-opcode": HonestRefusal,
		"unsupported-storage-layout": HonestRefusal, "rejected-feature": HonestRefusal,
		"unrecognized-dispatcher": HonestRefusal, "external-call-abstraction": HonestRefusal,
		"summary-unverified": HonestRefusal, "multi-call-ambiguous-call-site": HonestRefusal,
		"multi-call-inner-arg-unsupported": HonestRefusal, "multi-call-stmt-between-calls": HonestRefusal,
		"invariant-uninitialized": HonestRefusal, "invariant-unchecked-functions": HonestRefusal,
		"tool-error": ToolError, "unresolved-phi-source": ModelBug,
		"unresolved-branch-cond": ModelBug, "modelling-inconsistency": ModelBug,
		"solver-disagreement": ModelBug,
		"assertion-violated":  WitnessTriage, "expect-revert-violated": WitnessTriage,
	}
	if len(codes) != 25 {
		t.Fatalf("table has %d codes, want 25", len(codes))
	}
	for code, want := range codes {
		class, _, ok := Disposition("inconclusive (" + code + ": x)")
		if !ok || class != want {
			t.Errorf("code %q -> class %q ok=%v, want %q", code, class, ok, want)
		}
		// The sweep doubles as the switch-drift guard: every class the
		// switch emits must name a next action in the map.
		if dispositionAdvice[class] == "" {
			t.Errorf("code %q -> class %q with no advice row", code, class)
		}
	}
}

// TestDispositionAdviceCoversEveryClass pins the map/constant coupling: all
// nine exported class constants must carry a non-empty next action, so a
// class added to the const block without a `dispositionAdvice` row fails
// here rather than rendering an empty "next: ()" downstream. The count is
// the completeness guard: eight REASON_CODES classes + the runtime floor.
func TestDispositionAdviceCoversEveryClass(t *testing.T) {
	classes := []string{
		EscalateBound, EscalateFlag, EscalateSolver, EscalateRuntime,
		SpecRewrite, HonestRefusal, ToolError, ModelBug, WitnessTriage,
	}
	if len(classes) != 9 {
		t.Fatalf("class list has %d entries, want 9", len(classes))
	}
	for _, class := range classes {
		if dispositionAdvice[class] == "" {
			t.Errorf("dispositionAdvice[%q] is empty", class)
		}
	}
}
