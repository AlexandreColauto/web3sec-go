// Invariant verification — harness rung lines: rendering, bounded-K backing, and event-evidence recheck (split from invariantverification.go; pure structural move).

package sections

import (
	"fmt"
	"strings"

	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessSlotShapeBurn is r32b F3: the burn for a stored harness object
// that STATES a rung while a required field is blank. harnessRunLine
// returns ok=false for that shape (it cannot render a line), and both
// backing checks live under `if ok` — so before this, blanking ONE field
// (reproduced with exec="") silently dropped the invariant: no line, no
// problem, "audit PASS".
//
// The rule is the finding's, verbatim: only a run with NO rung at all may
// be skipped silently (the rung IS the claim; without it there is nothing
// to back). A stated rung with a blank required field is a shape no mapper
// writes — every bind writes kind, rung and exec together (cli.harnessField,
// autoproveEventData) — so it is a hand edit or a half-landed write, and it
// must burn naming the field that is missing. Returns "" when there is
// nothing to read (no harness object) or nothing claimed (no rung).
func harnessSlotShapeBurn(iid string, e validation.Value) string {
	h := validation.ObjAt(validation.ObjAt(e, "verification"), "harness")
	if h.Kind != validation.Obj {
		return "" // no harness object: no run, nothing to back
	}
	rung := validation.ObjStr(h, "rung")
	if rung == "" {
		return "" // no rung at all: the sanctioned silent skip
	}
	missing := []string{}
	for _, key := range []string{"kind", "exec"} {
		if validation.ObjStr(h, key) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf("%s: the stored harness object states rung %s but "+
		"carries no %s — the bind writes kind, rung and exec together, so "+
		"no mapper produced this slot (hand edit or a half-landed write); "+
		"a rung with a blank required field is not a run this section can "+
		"read, and it is not backed", iid, validation.PyReprStr(rung),
		strings.Join(missing, " and "))
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
	h := validation.ObjAt(validation.ObjAt(e, "verification"), "harness")
	if h.Kind != validation.Obj {
		return "", false
	}
	kind, rung, exec := validation.ObjStr(h, "kind"), validation.ObjStr(h, "rung"), validation.ObjStr(h, "exec")
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
		if class, advice, ok := harness.Disposition(validation.ObjStr(h, "summary")); ok {
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
	c := validation.ObjAt(validation.ObjAt(h, "proof"), "calls")
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
	if bk := validation.ObjAt(h, "bounded_k"); bk.Kind == validation.Int {
		return validation.IntText(bk), true
	}
	lb := validation.ObjAt(validation.ObjAt(validation.ObjAt(h, "proof"), "bounds"), "loop_bound")
	if lb.Kind == validation.Int {
		return validation.IntText(lb), true
	}
	return "", false
}

// harnessRungBacked returns "" when the invariant's stored harness rung
// is the outcome of the LAST harness_run event for it (events are the
// truth; the slot is the latest bind — if the slot disagrees with the
// newest event, somebody wrote to the slot WITHOUT an event: hand-edit,
// a refused bind whose unwind itself failed, or a version skew).
func harnessRungBacked(events []validation.Value, iid string,
	entry validation.Value) string {
	h := validation.ObjAt(validation.ObjAt(entry, "verification"), "harness")
	last := validation.VNull()
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		d := validation.ObjAt(ev, "data")
		if validation.ObjStr(d, "invariant") == iid {
			last = d
		}
	}
	if last.Kind != validation.Obj {
		return fmt.Sprintf("%s: verification.harness present with NO "+
			"harness_run event — the slot was not written by a mapper "+
			"(hand edit or failed unwind); the rung is not backed", iid)
	}
	// r22 F3: bounded_k is the field the DISPLAY line trusts most — a
	// event-less k can only mean "the run carried none"; any other
	// disagreement (slot 999999 vs event 100) is a hand-edit. Events
	// from pre-k mappers omit the key entirely and pass (null-vs-null).
	slotK, eventK := validation.ObjAt(h, "bounded_k"), validation.ObjAt(last, "bounded_k")
	if slotK.Kind != eventK.Kind ||
		(slotK.Kind == validation.Int && slotK.I != eventK.I) {
		return fmt.Sprintf("%s: stored bounded_k (%s) does not match the "+
			"LAST harness_run event (%s) — display state drifted from the "+
			"ledger", iid, pyKind(slotK), pyKind(eventK))
	}
	// r23 F1: the proof subtree feeds the DISPLAY (k= falls back to
	// proof.bounds.loop_bound, the poc: line counts proof.calls) — a
	// slot proof must equal the event's fingerprint, and a subtree under
	// an event that never fingerprinted proofs is exactly the
	// "hand-edit around the rails" shape: unbacked by construction.
	slotProof := validation.ObjAt(h, "proof")
	evDig := validation.ObjStr(last, "proof_sha256")
	if evDig == "" {
		if slotProof.Kind == validation.Obj {
			return fmt.Sprintf("%s: stored proof subtree has no event "+
				"digest to match (the last harness_run event predates "+
				"digesting or was written around a mapper) — the k=/poc: "+
				"lines render from UNBACKED bytes", iid)
		}
	} else if got := proofDigest(slotProof); got != evDig {
		return fmt.Sprintf("%s: stored proof subtree (sha %s) does not "+
			"match the LAST harness_run event's digest (%s) — display "+
			"state drifted from the ledger", iid, got[:12], evDig[:12])
	}
	for _, key := range []string{"kind", "rung", "exec", "summary"} {
		want := validation.ObjStr(h, key)
		got := validation.ObjStr(last, key)
		if want == "" || got == "" {
			// early harness_run events predate per-kind/summary
			// payloads; a field only ONE side carries is compared never,
			// but RUNG — the claim itself — is always present on both by
			// the mappers' own contract.
			if key == "rung" && want != "" && got == "" {
				return fmt.Sprintf("%s: the last harness_run event names "+
					"no rung for the stored %s — the slot is unbacked", iid,
					validation.PyReprStr(want))
			}
			// r32b F3's adjacent arm: the same field-level blank in the
			// EVENT side of `kind`. The slot's kind is what the display
			// line prints as the run's provenance ("INV-1: PROVEN-BOUNDED
			// (minicertora, …)") and what harnessEvidenceRecheck selects
			// the mapper by, so an event that carries NO kind cannot back
			// that render — no mapper writes a kindless event (the pre-r22
			// payload remark above predates the kind-keyed rails), so the
			// only shapes here are a hand edit and a half-land.
			if key == "kind" && want != "" && got == "" {
				return fmt.Sprintf("%s: the last harness_run event names "+
					"no kind for the stored rung %s — the slot's kind is "+
					"the run's provenance and no event carries it; the "+
					"slot is unbacked", iid,
					validation.PyReprStr(validation.ObjStr(h, "rung")))
			}
			continue
		}
		if want != got {
			return fmt.Sprintf("%s: stored harness rung (%s=%s) does not "+
				"match the LAST harness_run event (%s=%s) — display state "+
				"drifted from the ledger", iid, key, validation.PyReprStr(want),
				key, validation.PyReprStr(got))
		}
	}
	return ""
}

// harnessEvidenceRecheck re-derives what the event claims FROM the
// evidence it names ("" = consistent or not re-derivable by shape).
//
// r29b F1: the KIND is resolved FIRST, and every kind a bind can write is
// dispatched to its mapper — the rail is never switched off by a string.
// Before this, the arm below reached recheckMapRunEvidence for anything that
// was not exactly "minicertora", and that function returned "" for any kind
// outside {halmos, forge-fuzz} while its comment claimed "unknown kinds
// render no harness_runs line anyway" (false: harnessRunLine renders a line
// for ANY non-empty kind). A chain-valid forgery that edited the kind to
// "mythril" in the slot AND in the last harness_run event therefore audited
// green, printing "INV-1: PROVEN-BOUNDED (mythril, k=999999, EXEC-…)" over
// stdout whose own bytes said loop_bound 4.
func harnessEvidenceRecheck(c *state.Campaign,
	events []validation.Value, iid string, entry validation.Value) string {
	h := validation.ObjAt(validation.ObjAt(entry, "verification"), "harness")
	last := validation.VNull()
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		d := validation.ObjAt(ev, "data")
		if validation.ObjStr(d, "invariant") == iid {
			last = d
		}
	}
	if last.Kind != validation.Obj {
		return "" // harnessRungBacked already burns this shape
	}
	// The spelling is checked before anything is mapped: only the four
	// canonical kinds have mappers, and only the bind's own canonicalization
	// (cli.harnessKindFor / verifyAutoprove) can have written them. The
	// DISPLAY line renders from this same slot kind, so a spelling no mapper
	// knows is a rung whose claim cannot be reproduced from any evidence.
	kindStr := validation.ObjStr(h, "kind")
	kind, known := harness.NormalizeKind(kindStr)
	if !known || kindStr != string(kind) {
		return harnessKindBurn(iid, kindStr, known)
	}
	exec := validation.ObjStr(last, "exec")
	switch {
	case strings.HasPrefix(exec, "REPORT-") || kind == harnessReportKind:
		// Report provenance names the report-bound bind, which maps the
		// registered report bytes with harness.MapReport — the kind is not
		// what selects that mapper here, the evidence is, so this arm
		// re-derives for whatever canonical kind the slot carries (a
		// hand-written or pre-miniprover ledger may pair report provenance
		// with a scaffold kind) and the canonicality check above has already
		// refused every kind no mapper implements. This also covers
		// miniprover WRAPPED IN A SANDBOX EXEC (cli.verifyAutoprove writes
		// the --exec it was given): the old dispatch keyed on the exec prefix
		// first and recheckMapRunEvidence then skipped every kind outside
		// {halmos, forge-fuzz}, so a legitimate report-bound blessing with an
		// EXEC provenance was never re-derived at all.
		//
		// r33 F2: the ONE-PROOF-ONE-ROW rail runs FIRST here. It is a
		// question about the LEDGER (which row claimed this (pin, property)
		// pair first), not about the bytes, and the bind refuses the later
		// claim outright — so a pair the ledger already carries must burn
		// whatever the pinned bytes would have said.
		if msg := reportProofCollisionBurn(events, iid, last); msg != "" {
			return msg
		}
		return recheckRegistryEvidence(c, iid, h, last, kind, exec)
	case strings.HasPrefix(exec, "EXEC-"):
		return recheckExecEvidence(c, events, iid, entry, h, last, exec, kind)
	}
	// Neither provenance shape: no bind writes such a pair (the scaffold bind
	// writes the ledger's EXEC id, autoprove a REPORT- digest). A blessing
	// rung can not be left unre-derived for want of a prefix.
	return recheckUnknownProvenance(iid, last, exec)
}

// harnessReportKind is the fourth kind a bind writes: cli.verifyAutoprove's
// report-bound rung (cmd_verify_autoprove.go carries
// harness.Kind("miniprover") on both the slot and the event). Its mapper is
// harness.MapReport, not MapRun, so no MapRun-shaped rail can re-derive it —
// the report bytes recheckRegistryEvidence re-reads are the evidence.
//
// r33 F4/F5: the value and the kind/evidence pairing now live in package
// harness (harness.ReportKind, harness.ReportProvenanceReason), because the
// rule is the BIND's own write path; this name is kept as the sections-side
// spelling so the existing call sites stay readable.
const harnessReportKind = harness.ReportKind

// harnessKindBurn refuses a kind this audit cannot re-derive, naming the
// kind as the reason (r29b F1(b)): a blessing rung whose kind no mapper
// implements must burn, never be skipped. known=false is a kind outside the
// vocabulary; known=true is a spelling the bind never writes (only the
// canonical spelling can come from the bind's own kind resolution), which is
// the "MINICERTORA" half of the forgery.
func harnessKindBurn(iid, kindStr string, known bool) string {
	if !known {
		return fmt.Sprintf("%s: stored harness kind %s names no mapper "+
			"this audit can re-derive (a bind writes exactly halmos, "+
			"forge-fuzz or minicertora for an exec-bound rung and "+
			"miniprover for a report-bound one) — the rung cannot be "+
			"reproduced from any evidence, so it is not backed", iid,
			validation.PyReprStr(kindStr))
	}
	canon, _ := harness.NormalizeKind(kindStr)
	return fmt.Sprintf("%s: stored harness kind %s is not the canonical "+
		"spelling %s the bind writes (argparse restricts --kind to that "+
		"vocabulary, so no mapper produced this rung) — the rung is not "+
		"backed", iid, validation.PyReprStr(kindStr),
		validation.PyReprStr(string(canon)))
}

// recheckUnknownProvenance refuses a blessing rung whose event names an exec
// that is neither an EXEC- ledger id nor a REPORT- digest: no bind writes
// that provenance, so there is no evidence to re-derive the rung from. An
// inconclusive/counterexample-free run keeps the quiet behaviour (nothing on
// record blesses anything).
func recheckUnknownProvenance(iid string, last validation.Value,
	exec string) string {
	rung := validation.ObjStr(last, "rung")
	if rung != harness.RungProvedBounded &&
		rung != harness.RungCounterexample {
		return ""
	}
	return fmt.Sprintf("%s: the last harness_run event names exec %s, which "+
		"is neither an EXEC- ledger id nor a REPORT- digest — no bind writes "+
		"that provenance, so the %s rung is not backed", iid,
		validation.PyReprStr(exec), validation.PyReprStr(rung))
}
