// minicertora.go: MapMinicertora — the G8 third kind's outcome mapper —
// and MapMinicertoraInvoc, the bind/audit entry point that adds the
// invocation-level degenerate-bound floor.
// Where halmos/forge-fuzz print prose (outcome.go), MiniCertora prints a
// JSON-lines verdict stream: one object per line, exactly one of which is
// attributed to this invariant by the scaffold-pinned rule name
// (mspec.go). The scan is structural — a rule key, a verdict key, an exit
// status — and never reads prose.
//
// Fail-open-to-inconclusive law: inherited from outcome.go verbatim. A
// prover that disagrees with itself gets zero trust, so a malformed line,
// an abort line (no rule key), zero or two attributed lines, an
// exit-status/verdict disagreement and an unrecognised verdict all land
// inconclusive. The proof sidecar is captured for the three verdict rungs
// only (UNKNOWN included); every refusal returns a null sidecar rather
// than a partial one. That includes the report-contradiction refusal: an
// attributed line that contradicts its own exit status loses the sidecar
// too, because a prover that disagrees with itself gets zero trust and
// its own output is not campaign evidence.
//
// Degenerate-bound floor (r27 F1): the same law MapRun carries, on both
// axes this mapper can see. A PROVEN line whose OWN bounds.loop_bound is
// below 1 is not twin output at all — the twin raises for loop_bound < 1
// (miniprover/verifier/unit.py) — so it floors to inconclusive with the
// "degenerate-bound" vocabulary disposition.go already classifies as
// escalate-bound, and hands out no bounded_k (0 and negatives alike). The
// invocation axis is MapMinicertoraInvoc, on the SAME predicate MapRun
// asks (BoundFloors, r30 P1-1): a command that states a degenerate bound
// (--loop-bound 0), or one the invocation parse cannot read at all
// (--loop-bound '4, --loop-bound 4; echo x, --loop-bound $(nproc)),
// describes a run no tool can have executed, whatever the stdout says.
//
// Timeout law: it lives in the CALLER, but this mapper keeps its own
// fail-closed floor. `verify --harness-result` checks harnessTimedOut and
// maps a killed run to inconclusive before this function is ever invoked,
// and Task 4 wires a missing/non-int exit_status as -2 straight in here.
// A negative or absent exit status therefore maps to inconclusive
// regardless of the output bytes — no clean exit, never a rung — and the
// contradiction check keeps its positive-exit meaning (PROVEN 0,
// VIOLATED 1, UNKNOWN 2).
package harness

import (
	"fmt"
	"strings"

	"websec/internal/validation"
)

// The degenerate-bound refusal vocabulary, shared with outcome.go rather
// than re-worded: disposition.go classifies the "degenerate-bound" inner
// text as EscalateBound, so a second wording class here would silently
// drop the advice. The run form is mapHalmos's parsed-marker wording; the
// INVOCATION form is not spelled here at all — boundFloorSummary
// (outcome.go) is its one home, so the degenerate half ("…the invocation
// states no bound >= 1)") and the unreadable half ("…invocation-unreadable:
// <construct>)") can never drift apart between MapRun and this mapper
// (r30 P1-1).
const mcDegenerateRunSummary = "inconclusive (degenerate-bound: the run " +
	"states no bound >= 1)"

// MapMinicertora maps one MiniCertora run (the raw stdout bytes, the exec
// record's exit_status, and the scaffold-pinned rule name) onto the rung
// vocabulary of outcome.go, plus the proof sidecar captured verbatim.
// proof is VNull() when no verdict line was attributed or when the run is
// refused. boundedK is non-nil only for proved-bounded, and never below 1:
// a PROVEN line whose own bounds state a degenerate bound floors (see the
// package comment's degenerate-bound floor). Callers holding the exec
// command's bound flag want MapMinicertoraInvoc, which adds the
// invocation-level half of the same floor.
//
// The law is applied in stream order: blank lines are skipped, and the
// first line that is not a JSON object, that carries no rule key, or that
// duplicates an already attributed line decides the outcome.
func MapMinicertora(raw []byte, exitStatus int, ruleName string) (rung,
	summary string, proof validation.Value, boundedK *int) {
	if exitStatus < 0 {
		return RungInconclusive, "inconclusive (exit output unmapped)",
			validation.VNull(), nil
	}
	verdict, obj, refusal, ok := mcAttributed(raw, ruleName)
	if !ok {
		return RungInconclusive, refusal, validation.VNull(), nil
	}
	if want, known := mcExpectedExit(verdict); known && exitStatus >= 0 &&
		exitStatus != want {
		return RungInconclusive, fmt.Sprintf("inconclusive "+
			"(report-contradiction: exit %d with verdict %s)",
			exitStatus, verdict), validation.VNull(), nil
	}
	switch verdict {
	case "PROVEN":
		k, hasK := mcIntAt(obj, "bounds", "loop_bound")
		if hasK && k < 1 {
			// r27 F1: the line's own report states a bound the twin
			// refuses (loop_bound < 1), so these bytes are not twin
			// output — a blessing over zero (or negative) unrollings
			// is a proof about nothing. Floor the whole run: no rung,
			// no sidecar, no bounded_k (0, -1 and -2 alike).
			return RungInconclusive, mcDegenerateRunSummary,
				validation.VNull(), nil
		}
		if !hasK {
			return RungProvedBounded, "proved bounded",
				mcProof(obj), nil
		}
		return RungProvedBounded,
			fmt.Sprintf("proved bounded (k=%d)", k), mcProof(obj), &k
	case "VIOLATED":
		return RungCounterexample, mcCounterexampleSummary(obj),
			mcProof(obj), nil
	case "UNKNOWN":
		return RungInconclusive, mcUnknownSummary(obj), mcProof(obj), nil
	default:
		return RungInconclusive, "inconclusive (exit output unmapped)",
			validation.VNull(), nil
	}
}

// MapMinicertoraInvoc is the INVOCATION-level floor the bind and the audit
// share. The exec command can itself state a bound no tool would have run
// under, and the twin raises for loop_bound < 1 before a run ever starts,
// so a record claiming one describes a run no tool can have executed —
// whatever its stdout says. invBound is
// harness.InvocationBound(command): 0 for a command that names none,
// N >= 1 for a stated bound, and either FLOORING sentinel for a bound that
// cannot be honoured — BoundDegenerate (-1) for a stated flag below 1 and
// BoundUnreadable (-2) for a command string the parse cannot lex at all.
//
// The floor test is BoundFloors — the SAME predicate MapRun uses, never a
// hand-written `invBound == BoundDegenerate` (r30 P1-1): that narrower test
// caught a stated degenerate value and let an UNREADABLE command through,
// so a record whose command was `--loop-bound '4` (unmatched quote) or
// `--loop-bound 4; echo x` (a command list) or `--loop-bound $(nproc)` (an
// expansion in the value) bound proved-bounded over a run nothing could
// have executed. The wording comes from boundFloorSummary (outcome.go), the
// one home: "invocation-unreadable: <construct>" when the caller hands the
// construct in (optional variadic, exactly like MapRun, and the construct
// must be the SAME parse's InvocationBoundReason), the degenerate
// invocation wording otherwise. The inner class Disposition maps to
// EscalateBound either way, and the floor is total — no proof sidecar, no
// bounded_k.
//
// Every verdict on a floored invocation is refused, not just PROVEN: it is
// the FLAG the tool refuses (or the argv the parse cannot derive), so no
// verdict line under it is tool output either.
//
// MapMinicertora's own signature is untouched for its other callers; both
// the bind and section 11's re-derivation reach it through ONE dispatcher —
// harness.decideMappedKind, called from harness.DecideBound (r28b F3: the
// bind's whole decision, hash arm and Validate re-render included, moved
// here from cli.harnessMapBound, and sections.recheckExecEvidence /
// recheckInconclusive now call that same entry point) — so the audit
// reproduces the bind's decision byte-for-byte, the invocation-unreadable
// detail included (r30 P1-1).
func MapMinicertoraInvoc(raw []byte, exitStatus int, ruleName string,
	invBound int, unreadable ...string) (rung, summary string,
	proof validation.Value, boundedK *int) {
	if BoundFloors(invBound) {
		return RungInconclusive, boundFloorSummary(invBound, unreadable...),
			validation.VNull(), nil
	}
	rung, summary, proof, boundedK = MapMinicertora(raw, exitStatus, ruleName)
	if rung == RungProvedBounded && boundedK != nil && *boundedK < 1 {
		// Belt-and-braces: the mapper already floors a stated bound
		// below 1, so a bounded_k that tiny can only arrive through a
		// future mapper bug — and a proof about nothing must never
		// reach the slot however it got here.
		return RungInconclusive, mcDegenerateRunSummary,
			validation.VNull(), nil
	}
	return rung, summary, proof, boundedK
}

// mcAttributed scans the JSONL stream for the single verdict line whose
// rule field matches ruleName. ok=false carries the byte-exact refusal
// summary; verdict is the attributed line's own verdict string.
func mcAttributed(raw []byte, ruleName string) (verdict string,
	obj validation.Value, refusal string, ok bool) {
	var found validation.Value
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		v, err := validation.ParseOrdered([]byte(t))
		if err != nil || v.Kind != validation.Obj {
			return "", validation.VNull(),
				"inconclusive (output is not JSONL)", false
		}
		rv, hasRule := mcField(v, "rule")
		if !hasRule {
			return "", validation.VNull(), mcAbortSummary(v), false
		}
		if rv.Kind != validation.Str || rv.S != ruleName {
			continue
		}
		if seen {
			return "", validation.VNull(),
				"inconclusive (duplicate verdict lines for rule)",
				false
		}
		found, seen = v, true
	}
	if !seen {
		return "", validation.VNull(), fmt.Sprintf(
			"inconclusive (no verdict line for rule %s)", ruleName), false
	}
	return mcStr(found, "verdict"), found, "", true
}

// mcAbortSummary is the abort line's refusal text: the tool's own reason
// and details, with the details capped like every other excerpt. A line
// that cannot even name a reason reads "unknown" rather than empty.
func mcAbortSummary(obj validation.Value) string {
	reason := mcStr(obj, "reason")
	if reason == "" {
		reason = "unknown"
	}
	return "aborted: " + reason + ": " +
		truncateRunes(mcStr(obj, "details"), maxExcerpt)
}

// mcExpectedExit is the exit status a verdict claims for itself — the
// report-contradiction rail's table (PROVEN 0, VIOLATED 1, UNKNOWN 2).
// known=false for a verdict the vocabulary does not name.
func mcExpectedExit(verdict string) (int, bool) {
	switch verdict {
	case "PROVEN":
		return 0, true
	case "VIOLATED":
		return 1, true
	case "UNKNOWN":
		return 2, true
	default:
		return 0, false
	}
}

// mcCounterexampleSummary reads the witness excerpt: the failed
// assertion's expression, falling back to the tool's reason and then to
// the fixed "assertion-violated" label. The confidence flag is appended
// only for the two classes the architecture names, so a confirmed
// counterexample carries no flag.
func mcCounterexampleSummary(obj validation.Value) string {
	expr := mcStrAt(obj, "failed_assertion", "expression")
	if expr == "" {
		expr = mcStr(obj, "reason")
	}
	if expr == "" {
		expr = "assertion-violated"
	}
	summary := "counterexample: " + truncateRunes(expr, maxExcerpt)
	switch mcStr(obj, "confidence") {
	case "unconfirmed":
		summary += " [unconfirmed: crosses a havoc'd call]"
	case "modeled":
		summary += " [modeled]"
	}
	return summary
}

// mcUnknownSummary is the honest-UNKNOWN text: the tool's reason paired
// with its details, the details capped at maxExcerpt.
func mcUnknownSummary(obj validation.Value) string {
	reason := mcStr(obj, "reason")
	if reason == "" {
		reason = "unknown"
	}
	return fmt.Sprintf("inconclusive (%s: %s)", reason,
		truncateRunes(mcStr(obj, "details"), maxExcerpt))
}

// mcProof captures the verdict line's sidecar in the fixed key order
// tool_version, solc_version, spec_version, evm_version, confidence,
// reason, bounds, assumptions, warnings, ghosts, invariant, calls. Scalars
// and arrays are copied out of the parsed line as parsed — the tool's own
// caveat list is the honesty layer, and webv2 neither invents nor drops
// caveats.
//
// Task 4 (RULING-12KEY) added the last two keys:
//   - "invariant" (mcObjOr): the invariant-induction roll-up object
//     {name, per_function, init, witness_function} verbatim for invariant
//     verdict lines, null for rule lines.
//   - "calls" (mcArrOr): the counterexample's witness call sequence
//     verbatim; null when the line carries none. This is the array the
//     audit's derived "| poc: N calls bridged" suffix and the L4 bridge
//     read from stored state — before Task 4 the sidecar dropped it, so
//     that rendering could never fire off a real run.
//
// The rest of the counterexample witness (params, final_storage) and the
// tool's extra metadata deliberately do NOT ride along: they stay in the
// EXEC stdout artifact.
func mcProof(obj validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "tool_version", V: mcOr(obj, "tool_version")},
		validation.KV{K: "solc_version", V: mcOr(obj, "solc_version")},
		validation.KV{K: "spec_version", V: mcOr(obj, "spec_version")},
		validation.KV{K: "evm_version", V: mcOr(obj, "evm_version")},
		validation.KV{K: "confidence", V: mcOr(obj, "confidence")},
		validation.KV{K: "reason", V: mcOr(obj, "reason")},
		validation.KV{K: "bounds", V: mcBounds(obj)},
		validation.KV{K: "assumptions", V: mcArr(obj, "assumptions")},
		validation.KV{K: "warnings", V: mcArr(obj, "warnings")},
		validation.KV{K: "ghosts", V: mcArr(obj, "ghosts")},
		validation.KV{K: "invariant", V: mcObjOr(obj, "invariant")},
		validation.KV{K: "calls", V: mcArrOr(obj, "calls")},
	)
}

// mcBounds renders bounds as the fixed three-key object the audit reads
// (loop_bound, path_cap, solver_timeout_ms), each value taken verbatim.
// An absent bounds object, or one of another shape, renders those same
// three keys as null rather than dropping the key: the sidecar's shape is
// pinned by the schema, its values belong to the tool.
func mcBounds(obj validation.Value) validation.Value {
	b, ok := mcField(obj, "bounds")
	if !ok || b.Kind != validation.Obj {
		b = validation.VNull()
	}
	return validation.VObj(
		validation.KV{K: "loop_bound", V: mcOr(b, "loop_bound")},
		validation.KV{K: "path_cap", V: mcOr(b, "path_cap")},
		validation.KV{K: "solver_timeout_ms",
			V: mcOr(b, "solver_timeout_ms")},
	)
}

// mcOr is obj[key] verbatim, or null when the key (or the object itself)
// is absent.
func mcOr(obj validation.Value, key string) validation.Value {
	if v, ok := mcField(obj, key); ok {
		return v
	}
	return validation.VNull()
}

// mcArr is obj[key] verbatim when it is an array, the empty array when
// the field is absent (the schema's nullable-by-design shape), and null
// when the tool put some other shape there: the sidecar mirrors tool values
// verbatim; the schema pins the key set, not the value types (post-landing
// contract, see IMPROVEMENTS Wave L-core).
func mcArr(obj validation.Value, key string) validation.Value {
	v, ok := mcField(obj, key)
	switch {
	case !ok:
		return validation.VArr()
	case v.Kind == validation.Arr:
		return v
	default:
		return validation.VNull()
	}
}

// mcObjOr is obj[key] verbatim when it is an object, null otherwise.
// Unlike mcBounds (which rebuilds a fixed three-key shape) it filters
// NOTHING inside: the invariant roll-up is the prover's own report object
// and every inner key/array/null is admitted verbatim. Absent, null and a
// malformed non-object all render null — the sidecar never invents an
// object for a key that promises object-or-null (RULING-12KEY).
func mcObjOr(obj validation.Value, key string) validation.Value {
	if v, ok := mcField(obj, key); ok && v.Kind == validation.Obj {
		return v
	}
	return validation.VNull()
}

// mcArrOr is obj[key] verbatim when it is an array, null otherwise.
// It is deliberately NOT mcArr: for the witness `calls` slot, absent must
// stay distinguishable from an empty witness, so an absent field renders
// null rather than an invented empty array, and a malformed non-array value
// becomes null without inventing content (RULING-12KEY). Downstream, the
// audit's poc suffix keys on a NON-EMPTY array either way.
func mcArrOr(obj validation.Value, key string) validation.Value {
	if v, ok := mcField(obj, key); ok && v.Kind == validation.Arr {
		return v
	}
	return validation.VNull()
}

// mcField is dict.get(key) over a parsed JSONL line (absent vs null kept
// distinct by the ok flag).
func mcField(obj validation.Value, key string) (validation.Value, bool) {
	if obj.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, kv := range obj.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// mcStr is obj[key] as a string; an absent or non-string field reads "".
func mcStr(obj validation.Value, key string) string {
	if v, ok := mcField(obj, key); ok && v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// mcStrAt is obj[outer][inner] as a string; "" when either hop is absent
// or of another shape.
func mcStrAt(obj validation.Value, outer, inner string) string {
	if v, ok := mcField(obj, outer); ok && v.Kind == validation.Obj {
		return mcStr(v, inner)
	}
	return ""
}

// mcIntAt is obj[outer][inner] as an int. ok=false when the field is
// absent, null, of another shape, or an integer that does not fit int64
// (a big int is real data but never a loop bound we can name).
func mcIntAt(obj validation.Value, outer, inner string) (int, bool) {
	v, ok := mcField(obj, outer)
	if !ok || v.Kind != validation.Obj {
		return 0, false
	}
	n, ok := mcField(v, inner)
	if !ok || n.Kind != validation.Int || n.Big != "" {
		return 0, false
	}
	return int(n.I), true
}
