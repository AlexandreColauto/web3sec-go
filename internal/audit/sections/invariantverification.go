// Section 11: invariant verification — a CHECKED_AGAINST_CODE entry must be
// LOG-ANCHORED verified: a registered artifact AND a matching
// invariant.verified log event (the shared _is_verified verdict with the
// enforcing halves). A hand-edited registry claiming verification with any
// registered artifact is caught here, exactly like a hand-edited floor
// policy. Message-for-message with audit.py section 11.
//
// G8 harness runs (Task 18) ride along informationally: every invariant
// carrying verification.harness contributes one line to the presence-gated
// "harness_runs" key (uppercase rung label only for proved-bounded).
// Campaigns without the field — every golden campaign — serialize
// byte-identically to before (the key is omitted, not emptied).
package sections

import (
	"fmt"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// InvariantVerification is audit.py section 11: {checked, problems, ok}
// plus the presence-gated harness_runs lines.
func InvariantVerification(c *state.Campaign) (validation.Value, error) {
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return validation.Value{}, err
	}
	reg := objAt(links, "invariants") // Python .get("invariants", {})
	events, err := c.Events()
	if err != nil {
		return validation.Value{}, err
	}
	var problems []validation.Value
	var runs []validation.Value
	for _, iid := range sortedObjKeys(reg) {
		e := objAt(reg, iid)
		if e.Kind != validation.Obj {
			continue
		}
		if line, ok := harnessRunLine(iid, e); ok {
			runs = append(runs, validation.VStr(line))
		}
		if objStr(e, "status") != "CHECKED_AGAINST_CODE" {
			continue
		}
		if invariants.IsVerified(e, c, iid, events) {
			continue
		}
		artID := objStr(e, "verified_by")
		if artID == "" {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"%s: CHECKED_AGAINST_CODE without a verified_by artifact", iid)))
			continue
		}
		if _, err := c.Artifact(artID); err != nil {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"%s: verified_by %s is not a registered artifact",
				iid, validation.PyReprStr(artID))))
			continue
		}
		problems = append(problems, validation.VStr(fmt.Sprintf(
			"%s: verified_by %s has no matching invariant.verified log "+
				"event — hand-edited verification is not verification",
			iid, validation.PyReprStr(artID))))
	}
	out := []validation.KV{
		KV("checked", validation.VInt(int64(len(reg.O)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	}
	// Presence-gated: campaigns without a single verification.harness
	// field (every golden campaign) keep the exact historical bytes.
	if len(runs) > 0 {
		out = append(out, KV("harness_runs", validation.VArr(runs...)))
	}
	return validation.VObj(out...), nil
}

// harnessRunLine renders one invariant's verification.harness rung as the
// brief's line: "INV-3: PROVEN-BOUNDED (halmos, k=100, EXEC-7)" — the
// uppercase label is proved-bounded's alone; counterexample and
// inconclusive stay lowercase. ok=false when the entry carries no
// well-formed harness object (kind, rung and exec are all required).
//
// A minicertora counterexample whose proof sidecar carries a non-empty
// calls array additionally says so: " | poc: <n> calls bridged" (L4 — the
// witness a fork can replay). That suffix is a pure derivation from the
// stored sidecar's length: the audit never re-derives the sequence spec
// (harness.BridgeSequence owns that), and the label claims the witness
// EXISTS, not that it has been replayed.
func harnessRunLine(iid string, e validation.Value) (string, bool) {
	h := objAt(objAt(e, "verification"), "harness")
	if h.Kind != validation.Obj {
		return "", false
	}
	kind, rung, exec := objStr(h, "kind"), objStr(h, "rung"), objStr(h, "exec")
	if kind == "" || rung == "" || exec == "" {
		return "", false
	}
	var line string
	switch {
	case rung == "proved-bounded":
		if k, ok := harnessBoundK(h); ok {
			line = fmt.Sprintf("%s: PROVEN-BOUNDED (%s, k=%s, %s)",
				iid, kind, k, exec)
		} else {
			line = fmt.Sprintf("%s: PROVEN-BOUNDED (%s, %s)", iid, kind,
				exec)
		}
	// A minicertora inconclusive run that actually disposed of a reason
	// names its next action inline; the plumbing floors (no verdict line
	// at all) and every other kind keep the historical plain line.
	case kind == string(harness.MiniCertora) &&
		rung == harness.RungInconclusive:
		if class, advice, ok := harness.Disposition(objStr(h, "summary")); ok {
			line = fmt.Sprintf("%s: %s (%s, %s) | next: %s (%s)",
				iid, rung, kind, exec, advice, class)
		} else {
			line = fmt.Sprintf("%s: %s (%s, %s)", iid, rung, kind, exec)
		}
	default:
		line = fmt.Sprintf("%s: %s (%s, %s)", iid, rung, kind, exec)
	}
	if kind == string(harness.MiniCertora) &&
		rung == harness.RungCounterexample {
		if n, ok := proofCallCount(h); ok {
			line += fmt.Sprintf(" | poc: %d calls bridged", n)
		}
	}
	return line, true
}

// proofCallCount is the witness's call count: the proof sidecar's calls
// array when it is a non-empty array. ok=false when the sidecar carries
// no such array — a halmos/forge-fuzz entry has no proof sidecar at all,
// and an unattributed or witness-less minicertora line keeps its
// historical bytes.
func proofCallCount(h validation.Value) (int, bool) {
	c := objAt(objAt(h, "proof"), "calls")
	if c.Kind != validation.Arr || len(c.A) == 0 {
		return 0, false
	}
	return len(c.A), true
}

// harnessBoundK is the line's k text: bounded_k when it is an integer,
// otherwise the proof sidecar's bounds.loop_bound — the same
// exact-decimal-text precedence the CLI display uses
// (cmd_verify_harness.proofLoopBoundText), so a bound beyond int64
// renders verbatim rather than losing digits. ok=false for a null,
// absent, or non-integer value in both places.
func harnessBoundK(h validation.Value) (string, bool) {
	if bk := objAt(h, "bounded_k"); bk.Kind == validation.Int {
		return validation.IntText(bk), true
	}
	lb := objAt(objAt(objAt(h, "proof"), "bounds"), "loop_bound")
	if lb.Kind == validation.Int {
		return validation.IntText(lb), true
	}
	return "", false
}
