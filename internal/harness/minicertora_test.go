package harness

// minicertora_test.go (Task 2): MapMinicertora's branch table — the three
// verdict rungs, every refusal shape (abort line, no attributed line,
// duplicate lines, report contradiction, malformed JSONL, no clean exit)
// and the proof
// sidecar's fixed key order. Fixtures are fabricated JSONL transcript
// lines shaped after the documented MiniCertora verdict record; no prose
// scraping is ever involved.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// mcProven is a bounded proof at k=4: exit 0, confidence modeled.
const mcProven = `{"schema_version":"1","tool_version":"0.4.2","spec_version":"v0.1","solc_version":"0.8.36","evm_version":"paris","optimizer_enabled":false,"contract":"V.sol","rule":"inv_1","verdict":"PROVEN","confidence":"modeled","reason":null,"details":"","assumptions":["msg.value-default-zero","entry-binding:wrapper"],"bounds":{"loop_bound":4,"loop_bound_exhaustive":true,"path_cap":64,"solver_timeout_ms":30000},"warnings":[]}
`

// mcViolated is a counterexample at exit 1: an unconfirmed assertion
// violation (the witness rides in the EXEC stdout artifact, not here).
const mcViolated = `{"tool_version":"0.4.2","solc_version":"0.8.36","spec_version":"v0.1","evm_version":"paris","contract":"V.sol","rule":"inv_1","verdict":"VIOLATED","confidence":"unconfirmed","reason":"assertion-violated","details":"","assumptions":["external-call-abstraction"],"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},"failed_assertion":{"expression":"total >= before"},"params":{"x":"2"},"calls":[],"final_storage":{"total":"0"}}
`

// mcUnknown is an honest UNKNOWN at exit 2: the unrolling exhausted its
// loop bound, so the run is inconclusive with a named reason.
const mcUnknown = `{"contract":"V.sol","rule":"inv_1","verdict":"UNKNOWN","confidence":"modeled","reason":"loop-bound-may-be-exceeded","details":"unrolling exhausted at k=4","assumptions":[],"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000}}
`

// mcAbort is the tool's abort line: no "rule" key at all, so it can never
// be attributed to an invariant.
const mcAbort = `{"verdict":"UNKNOWN","reason":"tool-error","details":"spec file unreadable"}
`

// mcGhosts carries a ghosts array (the fixtures above never do): the
// sidecar must copy it verbatim, not rebuild it.
const mcGhosts = `{"rule":"inv_1","verdict":"UNKNOWN","reason":"modeled-havoc","details":"","assumptions":[1,"two",null],"warnings":[{"code":"w1"}],"ghosts":[{"slot":"total","expr":"x+1"}]}
`

// mcVerdictKeys is the proof sidecar's fixed key order (the determinism
// law: downstream schemas and audits read this order). Task 4 extended it
// from ten to twelve keys: "invariant" (mcObjOr) and "calls" (mcArrOr).
var mcVerdictKeys = []string{"tool_version", "solc_version",
	"spec_version", "evm_version", "confidence", "reason", "bounds",
	"assumptions", "warnings", "ghosts", "invariant", "calls"}

// mcInvariantHandled is a PROVEN invariant-induction line: the report names
// the checked entrypoints as an ARRAY of per-function checks and the init
// check object (the shape minicertora's invariant roll-up prints). The
// sidecar copies the whole object verbatim.
const mcInvariantHandled = `{"tool_version":"0.4.2","solc_version":"0.8.36","spec_version":"v0.1","contract":"Capped.sol","rule":"inv_1","verdict":"PROVEN","confidence":"modeled","reason":null,"bounds":{"loop_bound":4,"loop_bound_exhaustive":true,"path_cap":64,"solver_timeout_ms":30000},"assumptions":["invariant-one-step-induction"],"invariant":{"name":"cap_respected","per_function":[{"selector":"0xd0e30db0","function":"deposit","kind":"proved","reason":null,"details":""},{"selector":"0x8da5cb5b","function":"setCap","kind":"proved","reason":null,"details":""}],"init":{"selector":"constructor","function":"constructor","kind":"proved","reason":null,"details":""},"witness_function":null}}` + "\n"

// mcInvariantUninitialized is the same report shape with `init` null (the
// contract declares no constructor): verbatim means the null rides.
const mcInvariantUninitialized = `{"contract":"Capped.sol","rule":"inv_1","verdict":"UNKNOWN","reason":"invariant-uninitialized","bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},"invariant":{"name":"cap_respected","per_function":[{"selector":"0xd0e30db0","function":"deposit","kind":"proved","reason":null,"details":""}],"init":null,"witness_function":null}}` + "\n"

// mcCallsWitness is a counterexample whose calls array carries the bridged
// witness (mixed trailing null on purpose: verbatim, no filtering).
const mcCallsWitness = `{"contract":"V.sol","rule":"inv_1","verdict":"VIOLATED","confidence":"unconfirmed","reason":"assertion-violated","failed_assertion":{"expression":"total >= before"},"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},"calls":[{"step":1,"function":"withdraw","target":"0x1111111111111111111111111111111111111111","args":["1000"],"env":{"msg.sender":"0x2222222222222222222222222222222222222222","msg.value":"0"},"reverted":false,"reentrant":false,"overrides":{}},{"step":2,"function":"withdraw","target":"0x1111111111111111111111111111111111111111","args":["2000"],"env":{"msg.sender":"0x3333333333333333333333333333333333333333","msg.value":"0"},"reverted":true,"reentrant":false,"overrides":{}}]}
`

// TestMapMinicertora is the mapping table: each row is one raw stdout
// byte string plus the exec record's exit_status, and pins the rung, the
// byte-exact summary and whether a proof sidecar was captured.
func TestMapMinicertora(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		exit    int
		rule    string
		rung    string
		summary string
		k       int
		hasK    bool
		proof   bool
	}{
		{
			name: "proven", raw: mcProven, exit: 0, rule: "inv_1",
			rung: RungProvedBounded, summary: "proved bounded (k=4)",
			k: 4, hasK: true, proof: true,
		},
		{
			name: "violated", raw: mcViolated, exit: 1, rule: "inv_1",
			rung: RungCounterexample,
			summary: "counterexample: total >= before" +
				" [unconfirmed: crosses a havoc'd call]",
			proof: true,
		},
		{
			name: "unknown", raw: mcUnknown, exit: 2, rule: "inv_1",
			rung: RungInconclusive,
			summary: "inconclusive (loop-bound-may-be-exceeded: " +
				"unrolling exhausted at k=4)",
			proof: true,
		},
		{
			name: "abort line", raw: mcAbort, exit: 0, rule: "inv_1",
			rung:    RungInconclusive,
			summary: "aborted: tool-error: spec file unreadable",
		},
		{
			name: "wrong rule name", raw: mcProven, exit: 0,
			rule: "inv_2", rung: RungInconclusive,
			summary: "inconclusive (no verdict line for rule inv_2)",
		},
		{
			name: "contradiction", raw: mcProven, exit: 1, rule: "inv_1",
			rung: RungInconclusive,
			summary: "inconclusive (report-contradiction: exit 1 " +
				"with verdict PROVEN)",
		},
		{
			name: "malformed json", raw: `{"rule":"inv_1","verdict":"`,
			exit: 0, rule: "inv_1", rung: RungInconclusive,
			summary: "inconclusive (output is not JSONL)",
		},
		{
			name: "non-object json", raw: "42\n", exit: 0, rule: "inv_1",
			rung:    RungInconclusive,
			summary: "inconclusive (output is not JSONL)",
		},
		{
			name: "empty bytes", raw: "", exit: 0, rule: "inv_1",
			rung:    RungInconclusive,
			summary: "inconclusive (no verdict line for rule inv_1)",
		},
		{
			name: "duplicate lines", raw: mcProven + mcProven, exit: 0,
			rule: "inv_1", rung: RungInconclusive,
			summary: "inconclusive (duplicate verdict lines for rule)",
		},
		{
			name: "blank lines skipped",
			raw:  "\n   \n" + mcProven + "\n\t\n", exit: 0, rule: "inv_1",
			rung: RungProvedBounded, summary: "proved bounded (k=4)",
			k: 4, hasK: true, proof: true,
		},
		{
			// No clean exit means no rung: a negative exit_status
			// (or a missing one, which Task 4 wires as -2) refuses
			// before the bytes are even read, so even a PROVEN
			// line cannot promote. See the doc comment's
			// fail-closed floor.
			name: "PROVEN at -1 refused", raw: mcProven, exit: -1,
			rule: "inv_1", rung: RungInconclusive,
			summary: "inconclusive (exit output unmapped)",
		},
		{
			name: "VIOLATED at -1 refused", raw: mcViolated, exit: -1,
			rule: "inv_1", rung: RungInconclusive,
			summary: "inconclusive (exit output unmapped)",
		},
		{
			name: "PROVEN at -2 refused", raw: mcProven, exit: -2,
			rule: "inv_1", rung: RungInconclusive,
			summary: "inconclusive (exit output unmapped)",
		},
		{
			name: "unmapped verdict",
			raw:  `{"rule":"inv_1","verdict":"ERROR"}` + "\n",
			exit: 0, rule: "inv_1", rung: RungInconclusive,
			summary: "inconclusive (exit output unmapped)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rung, summary, proof, boundedK := MapMinicertora(
				[]byte(tc.raw), tc.exit, tc.rule)
			if rung != tc.rung {
				t.Errorf("rung = %q, want %q", rung, tc.rung)
			}
			if summary != tc.summary {
				t.Errorf("summary = %q, want %q", summary, tc.summary)
			}
			if tc.hasK {
				if boundedK == nil {
					t.Fatalf("boundedK = nil, want %d", tc.k)
				}
				if *boundedK != tc.k {
					t.Errorf("boundedK = %d, want %d", *boundedK, tc.k)
				}
			} else if boundedK != nil {
				t.Errorf("boundedK = %d, want nil", *boundedK)
			}
			if !tc.proof {
				if proof.Kind != validation.Null {
					t.Errorf("proof = %s, want null",
						validation.CanonCompact(proof))
				}
				return
			}
			if proof.Kind != validation.Obj {
				t.Fatalf("proof kind = %c, want object", proof.Kind)
			}
			if len(proof.O) != len(mcVerdictKeys) {
				t.Fatalf("proof has %d keys, want %d: %s", len(proof.O),
					len(mcVerdictKeys),
					validation.CanonCompact(proof))
			}
			for i, kv := range proof.O {
				if kv.K != mcVerdictKeys[i] {
					t.Errorf("proof key %d = %q, want %q", i, kv.K,
						mcVerdictKeys[i])
				}
			}
		})
	}
}

// mcProofField is proof[key] (absent reads as null).
func mcProofField(t *testing.T, proof validation.Value,
	key string) validation.Value {
	t.Helper()
	for _, kv := range proof.O {
		if kv.K == key {
			return kv.V
		}
	}
	t.Fatalf("proof has no key %q", key)
	return validation.VNull()
}

// TestMapMinicertoraProofVerbatim pins the sidecar's VALUE law: scalars
// and arrays are copied out of the parsed line exactly as parsed (never
// rebuilt, never re-ordered), absent fields render null, and the
// counterexample witness (params/calls/final_storage) deliberately stays
// out of the sidecar.
func TestMapMinicertoraProofVerbatim(t *testing.T) {
	_, _, proof, _ := MapMinicertora([]byte(mcProven), 0, "inv_1")
	want := map[string]string{
		"tool_version": `"0.4.2"`,
		"solc_version": `"0.8.36"`,
		"spec_version": `"v0.1"`,
		"evm_version":  `"paris"`,
		"confidence":   `"modeled"`,
		"reason":       `null`,
		"bounds": `{"loop_bound":4,"path_cap":64,` +
			`"solver_timeout_ms":30000}`,
		"assumptions": `["msg.value-default-zero",` +
			`"entry-binding:wrapper"]`,
		"warnings": `[]`,
		"ghosts":   `[]`,
		// Task 4: a rule line carries neither an invariant roll-up nor a
		// witness — both keys ride as null (mcObjOr / mcArrOr), never
		// dropped and never invented as an empty array.
		"invariant": `null`,
		"calls":     `null`,
	}
	for key, wantCanon := range want {
		got := validation.CanonCompact(mcProofField(t, proof, key))
		if got != wantCanon {
			t.Errorf("proof.%s = %s, want %s", key, got, wantCanon)
		}
	}

	// The witness parameters and the tool's extra metadata never ride along
	// (the calls array DOES — it is the 12th key, pinned below).
	canon := validation.CanonCompact(proof)
	for _, absent := range []string{"params", "final_storage",
		"optimizer_enabled", "schema_version", "loop_bound_exhaustive"} {
		if strings.Contains(canon, absent) {
			t.Errorf("proof leaked %q: %s", absent, canon)
		}
	}
}

// TestMapMinicertoraProofInvariantVerbatim pins RULING-12KEY's 11th key:
// mcObjOr copies the prover's invariant roll-up object whole — inner arrays,
// inner objects and the init null included — and renders null for anything
// that is not an object. The sidecar filters nothing inside the object (the
// per_function entry key order below is the proof).
func TestMapMinicertoraProofInvariantVerbatim(t *testing.T) {
	_, _, proof, _ := MapMinicertora([]byte(mcInvariantHandled), 0, "inv_1")
	inv := mcProofField(t, proof, "invariant")
	if inv.Kind != validation.Obj {
		t.Fatalf("proof.invariant = %s, want the verbatim object",
			validation.CanonCompact(inv))
	}
	want := `{"init":{"details":"","function":"constructor","kind":"proved",` +
		`"reason":null,"selector":"constructor"},"name":"cap_respected",` +
		`"per_function":[{"details":"","function":"deposit","kind":"proved",` +
		`"reason":null,"selector":"0xd0e30db0"},{"details":"",` +
		`"function":"setCap","kind":"proved","reason":null,` +
		`"selector":"0x8da5cb5b"}],"witness_function":null}`
	if got := validation.CanonCompact(inv); got != want {
		t.Errorf("proof.invariant = %s\nwant %s", got, want)
	}
	// Verbatim includes the prover's own inner key order: per_function comes
	// before init here, and the inner check object keeps name/selector/…
	var keys []string
	for _, kv := range inv.O {
		keys = append(keys, kv.K)
	}
	if got := strings.Join(keys, ","); got !=
		"name,per_function,init,witness_function" {
		t.Errorf("invariant keys = %s, want the prover's own order", got)
	}
}

// TestMapMinicertoraProofInvariantInitNull pins the init-null case from the
// invariant-no-constructor shape: null is a VALUE the prover printed, so it
// must ride through as null rather than being dropped or defaulted.
func TestMapMinicertoraProofInvariantInitNull(t *testing.T) {
	_, _, proof, _ := MapMinicertora([]byte(mcInvariantUninitialized), 2, "inv_1")
	inv := mcProofField(t, proof, "invariant")
	if init, ok := mcField(inv, "init"); !ok || init.Kind != validation.Null {
		t.Fatalf("proof.invariant.init = %s, want null",
			validation.CanonCompact(init))
	}
	pf, _ := mcField(inv, "per_function")
	if pf.Kind != validation.Arr || len(pf.A) != 1 ||
		mcStr(pf.A[0], "function") != "deposit" {
		t.Fatalf("proof.invariant.per_function = %s",
			validation.CanonCompact(pf))
	}
}

// TestMapMinicertoraProofInvariantNonObject pins the shape floor: a scalar,
// array or absent invariant field renders null (mcObjOr) — the sidecar never
// invents an object and never stores a malformed shape under the key.
func TestMapMinicertoraProofInvariantNonObject(t *testing.T) {
	for _, raw := range []string{
		`{"rule":"inv_1","verdict":"PROVEN","confidence":"modeled","invariant":"nope"}`,
		`{"rule":"inv_1","verdict":"PROVEN","confidence":"modeled","invariant":[1,2]}`,
		`{"rule":"inv_1","verdict":"PROVEN","confidence":"modeled","invariant":null}`,
	} {
		_, _, proof, _ := MapMinicertora([]byte(raw+"\n"), 0, "inv_1")
		if got := mcProofField(t, proof, "invariant"); got.Kind != validation.Null {
			t.Errorf("invariant %s → %s, want null", raw,
				validation.CanonCompact(got))
		}
	}
}

// TestMapMinicertoraProofCallsVerbatim pins RULING-12KEY's 12th key: the
// counterexample's calls array rides verbatim (the L4 bridge and the audit's
// poc suffix read it from here). An empty array is a VALUE and rides as [];
// an absent or non-array field renders null — mcArrOr never invents an
// empty list, which is what keeps "no witness" distinguishable from
// "an empty witness".
func TestMapMinicertoraProofCallsVerbatim(t *testing.T) {
	_, _, proof, _ := MapMinicertora([]byte(mcCallsWitness), 1, "inv_1")
	calls := mcProofField(t, proof, "calls")
	if calls.Kind != validation.Arr || len(calls.A) != 2 {
		t.Fatalf("proof.calls = %s, want the 2-call witness",
			validation.CanonCompact(calls))
	}
	if got := mcStr(calls.A[1], "function"); got != "withdraw" {
		t.Errorf("calls[1].function = %q", got)
	}
	if reverted, ok := mcField(calls.A[1], "reverted"); !ok ||
		reverted.Kind != validation.Bool || !reverted.B {
		t.Errorf("calls[1].reverted = %s, want true",
			validation.CanonCompact(reverted))
	}
	// The verbatim law reaches inside each entry: the prover's inner key
	// order (step, function, target, args, env, reverted, reentrant,
	// overrides) survives.
	var keys []string
	for _, kv := range calls.A[0].O {
		keys = append(keys, kv.K)
	}
	if got := strings.Join(keys, ","); got !=
		"step,function,target,args,env,reverted,reentrant,overrides" {
		t.Errorf("calls[0] keys = %s, want the prover's own order", got)
	}

	// Empty array vs null: an empty witness is a value.
	_, _, proof, _ = MapMinicertora([]byte(mcViolated), 1, "inv_1")
	if got := validation.CanonCompact(mcProofField(t, proof, "calls")); got != "[]" {
		t.Errorf("proof.calls = %s, want []", got)
	}
	// Absent and malformed render null (ncArrOr's whole point).
	for _, raw := range []string{
		`{"rule":"inv_1","verdict":"VIOLATED","reason":"assertion-violated"}`,
		`{"rule":"inv_1","verdict":"VIOLATED","reason":"assertion-violated","calls":"nope"}`,
		`{"rule":"inv_1","verdict":"VIOLATED","reason":"assertion-violated","calls":null}`,
	} {
		_, _, proof, _ := MapMinicertora([]byte(raw+"\n"), 1, "inv_1")
		if got := mcProofField(t, proof, "calls"); got.Kind != validation.Null {
			t.Errorf("calls %s → %s, want null", raw,
				validation.CanonCompact(got))
		}
	}
}

// TestMapMinicertoraProofArraysVerbatim pins that assumptions, warnings
// and ghosts are copied as-is — element order, mixed kinds and nested
// objects included — because the tool's own caveat list is the honesty
// layer and webv2 must neither invent nor drop caveats.
func TestMapMinicertoraProofArraysVerbatim(t *testing.T) {
	_, _, proof, _ := MapMinicertora([]byte(mcGhosts), 2, "inv_1")
	want := map[string]string{
		"assumptions": `[1,"two",null]`,
		"warnings":    `[{"code":"w1"}]`,
		// Canon sorts nested keys, so the ghost's own key order is
		// asserted on the value below.
		"ghosts": `[{"expr":"x+1","slot":"total"}]`,
		// No bounds field on the line: the fixed shape still renders.
		"bounds": `{"loop_bound":null,"path_cap":null,` +
			`"solver_timeout_ms":null}`,
	}
	for key, wantCanon := range want {
		got := validation.CanonCompact(mcProofField(t, proof, key))
		if got != wantCanon {
			t.Errorf("proof.%s = %s, want %s", key, got, wantCanon)
		}
	}

	// Verbatim means the element's own key order survives too: the
	// ghost object keeps slot before expr.
	ghosts := mcProofField(t, proof, "ghosts")
	if len(ghosts.A) != 1 || ghosts.A[0].Kind != validation.Obj {
		t.Fatalf("ghosts = %s", validation.CanonCompact(ghosts))
	}
	var keys []string
	for _, kv := range ghosts.A[0].O {
		keys = append(keys, kv.K)
	}
	if got := strings.Join(keys, ","); got != "slot,expr" {
		t.Errorf("ghost keys = %s, want slot,expr", got)
	}
}

// TestMapMinicertoraExcerptCap pins the ≤120-rune excerpt ceiling on
// counterexample expressions and on inconclusive details.
func TestMapMinicertoraExcerptCap(t *testing.T) {
	long := strings.Repeat("x", 150)
	violated := `{"rule":"inv_1","verdict":"VIOLATED","confidence":` +
		`"confirmed","reason":"assertion-violated",` +
		`"failed_assertion":{"expression":"` + long + `"}}`
	rung, summary, _, _ := MapMinicertora([]byte(violated), 1, "inv_1")
	if rung != RungCounterexample {
		t.Fatalf("rung = %q, want %q", rung, RungCounterexample)
	}
	want := "counterexample: " + strings.Repeat("x", maxExcerpt)
	if summary != want {
		t.Errorf("summary = %q (len %d), want %q", summary,
			len([]rune(summary)), want)
	}

	unknown := `{"rule":"inv_1","verdict":"UNKNOWN","reason":"r",` +
		`"details":"` + long + `"}`
	_, summary, _, _ = MapMinicertora([]byte(unknown), 2, "inv_1")
	want = "inconclusive (r: " + strings.Repeat("x", maxExcerpt) + ")"
	if summary != want {
		t.Errorf("summary = %q (len %d), want %q", summary,
			len([]rune(summary)), want)
	}
}

// TestMapMinicertoraCounterexampleFallback pins the summary's fallback
// chain: an absent/blank expression falls back to the tool's reason, then
// to the fixed "assertion-violated" label, and the confidence flag is
// appended only for the two flagged classes.
func TestMapMinicertoraCounterexampleFallback(t *testing.T) {
	noExpr := `{"rule":"inv_1","verdict":"VIOLATED","confidence":` +
		`"confirmed","reason":"inner-call-reverted"}`
	_, summary, _, _ := MapMinicertora([]byte(noExpr), 1, "inv_1")
	if summary != "counterexample: inner-call-reverted" {
		t.Errorf("summary = %q", summary)
	}

	bare := `{"rule":"inv_1","verdict":"VIOLATED"}`
	_, summary, _, _ = MapMinicertora([]byte(bare), 1, "inv_1")
	if summary != "counterexample: assertion-violated" {
		t.Errorf("summary = %q", summary)
	}

	modeled := `{"rule":"inv_1","verdict":"VIOLATED","confidence":` +
		`"modeled","reason":"assertion-violated",` +
		`"failed_assertion":{"expression":"a == b"}}`
	_, summary, _, _ = MapMinicertora([]byte(modeled), 1, "inv_1")
	want := "counterexample: a == b [modeled]"
	if summary != want {
		t.Errorf("summary = %q, want %q", summary, want)
	}
}

// TestMapMinicertoraContradictionPerVerdict pins the exit-status rail for
// all three verdicts (PROVEN@≠0, VIOLATED@≠1, UNKNOWN@≠2) and the
// matching pair passing through untouched.
func TestMapMinicertoraContradictionPerVerdict(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		exit    int
		ok      bool
		summary string
	}{
		{name: "violated at 0", raw: mcViolated, exit: 0,
			summary: "inconclusive (report-contradiction: exit 0 " +
				"with verdict VIOLATED)"},
		{name: "unknown at 0", raw: mcUnknown, exit: 0,
			summary: "inconclusive (report-contradiction: exit 0 " +
				"with verdict UNKNOWN)"},
		{name: "proven at 2", raw: mcProven, exit: 2,
			summary: "inconclusive (report-contradiction: exit 2 " +
				"with verdict PROVEN)"},
		{name: "violated at 1 passes", raw: mcViolated, exit: 1,
			ok: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rung, summary, proof, _ := MapMinicertora(
				[]byte(tc.raw), tc.exit, "inv_1")
			if tc.ok {
				if rung != RungCounterexample {
					t.Errorf("rung = %q", rung)
				}
				return
			}
			if rung != RungInconclusive {
				t.Errorf("rung = %q, want inconclusive", rung)
			}
			if summary != tc.summary {
				t.Errorf("summary = %q, want %q", summary, tc.summary)
			}
			if proof.Kind != validation.Null {
				t.Errorf("contradiction kept a proof sidecar: %s",
					validation.CanonCompact(proof))
			}
		})
	}
}

// TestMapMinicertoraBoundsMissing pins the bounds value law directly: a
// non-integer loop_bound (or a big int that cannot be an int) drops the
// k from the summary and leaves bounded_k null.
func TestMapMinicertoraBoundsMissing(t *testing.T) {
	for _, raw := range []string{
		`{"rule":"inv_1","verdict":"PROVEN","bounds":{}}`,
		`{"rule":"inv_1","verdict":"PROVEN"}`,
		`{"rule":"inv_1","verdict":"PROVEN",` +
			`"bounds":{"loop_bound":"4"}}`,
		`{"rule":"inv_1","verdict":"PROVEN",` +
			`"bounds":{"loop_bound":99999999999999999999}}`,
	} {
		rung, summary, proof, boundedK := MapMinicertora(
			[]byte(raw), 0, "inv_1")
		if rung != RungProvedBounded || summary != "proved bounded" {
			t.Errorf("%s: got %q/%q", raw, rung, summary)
		}
		if boundedK != nil {
			t.Errorf("%s: boundedK = %d, want nil", raw, *boundedK)
		}
		if proof.Kind != validation.Obj {
			t.Errorf("%s: proof kind = %c", raw, proof.Kind)
		}
	}
}
