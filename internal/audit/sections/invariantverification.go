// Section 11: invariant verification — a CHECKED_AGAINST_CODE entry must be
// LOG-ANCHORED verified: a registered artifact AND a matching
// invariant.verified log event (the shared _is_verified verdict with the
// enforcing halves). A hand-edited registry claiming verification with any
// registered artifact is caught here, exactly like a hand-edited floor
// policy. Message-for-message with audit.py section 11.
//
// G8 harness runs (Task 18) ride along informationally: every invariant
// carrying verification.harness contributes one line to the presence-gated
// "harness_runs" key (uppercase rung label only for proved-bounded), and —
// L-defer T5 — the campaign's stored MiniCertora refusals contribute ONE
// further derived line after those per-invariant lines (the L3 full form:
// a class histogram plus the top reason codes, see proverrefusals.go).
// Campaigns without the field — every golden campaign — serialize
// byte-identically to before (the key is omitted, not emptied).
package sections

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// stdoutUnreadableBurn is the ONE refusal for a captured stdout the audit
// could not read: the rung is named, the exec is named, and the errno the
// shared reader observed is carried verbatim. All three rung arms that
// re-derive from stored bytes return exactly this.
func stdoutUnreadableBurn(iid, exec string, err error) string {
	return fmt.Sprintf("%s: exec %s stdout unreadable (%v) — the "+
		"evidence behind the rung cannot be re-checked", iid, exec, err)
}

// stdoutAbsent reports whether a harness.ReadExecStdout failure is the
// documented ABSENCE of the capture — nothing was ever captured
// (ErrNoCapturedStdout), or the file the record names is not there any more
// (a pruned/aged-out witness) — as opposed to a READ failure on a capture
// that IS present. Only the not-exist class is folded into absence; EACCES,
// ENOTDIR and EIO are refusals, the same contract as
// validation.ListPrefixedOptional (r44b P3-b).
func stdoutAbsent(err error) bool {
	if errors.Is(err, harness.ErrNoCapturedStdout) {
		return true
	}
	return errors.Is(err, os.ErrNotExist)
}

// unbackedSuffix qualifies a harness_runs line whose blessing THIS section
// could not back (harnessRungBacked or harnessEvidenceRecheck burned it).
// It closes the line, after every derived clause, and is emitted only on
// that failure — a fully backed rung keeps its historical bytes.
const unbackedSuffix = " (UNBACKED)"

// InvariantVerification is audit.py section 11: {checked, problems, ok}
// plus the presence-gated harness_runs lines: one per invariant carrying a
// well-formed verification.harness object, then — when the campaign stores
// at least one inconclusive MiniCertora record — the one derived refusal
// histogram line (L-defer T5, proverrefusals.go). A line whose own backing
// check burned in this same pass carries the unbackedSuffix.
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
	tally := newRefusalTally()
	for _, iid := range sortedObjKeys(reg) {
		e := objAt(reg, iid)
		if e.Kind != validation.Obj {
			continue
		}
		line, ok := harnessRunLine(iid, e)
		// r32b F3: harnessRunLine returns ok=false for a slot that STATES
		// a rung while kind or exec is blank — and BOTH backing checks
		// used to live inside `if ok`, so ONE empty string dropped the
		// invariant with no line and NO problem ("audit PASS"). Only a run
		// with no rung at all may be skipped silently; every other
		// required-field blank burns, naming the field.
		if burn := harnessSlotShapeBurn(iid, e); burn != "" {
			problems = append(problems, validation.VStr(burn))
		}
		if ok {
			// r26 D4: the display line and the burn are ONE observation.
			// This section can refuse to back a blessing (a pruned
			// REPORT row, a deleted EXEC) while still printing the
			// unqualified rung — a consumer that reads only
			// harness_runs then sees a blessing the section itself just
			// called unbacked. The qualifier below is driven by the
			// section's OWN two backing checks for THIS invariant
			// (their non-empty return, not a re-grep of problem text),
			// so there is no second derivation to drift.
			unbacked := false
			// r21 F7: the display slot alone used to be beyond reproach —
			// §8's "audit cross-checks claims against events" is NOW
			// true for harness rungs: the CURRENT rung (kind, rung, exec,
			// summary — the summary is the mapper's full rendering, so a
			// hand-edit or an unrecoverable half-land can't match) must
			// appear as the LAST harness_run event for the invariant.
			if msg := harnessRungBacked(events, iid, e); msg != "" {
				problems = append(problems, validation.VStr(msg))
				unbacked = true
			}
			// r24 (sharpest untried idea): the slot↔event rails bind the
			// display to the LEDGER — but a chain-valid forgery edits the
			// events too, and only the EXEC OUTPUT the event names is the
			// original evidence. Re-derive the mapper's numbers from the
			// artifacts at AUDIT time through the BIND'S OWN decision
			// entry point (r28b F3: harness.DecideBound — recorded-hash
			// arm, Validate re-render and unbound suffix included, over
			// the exec stdout, the record's own exit status / timeout bit
			// / invocation bound and the scaffold artifact bytes), while
			// autoprove digests must exist in the registry. A lie then
			// needs the stdout bytes or a registry row to match too —
			// write-time convention becomes an audit-time invariant.
			if msg := harnessEvidenceRecheck(c, events, iid, e); msg != "" {
				problems = append(problems, validation.VStr(msg))
				unbacked = true
			}
			// The qualifier closes the line: after the advice clause
			// (" | next: …") and after the witness label (" | poc: …"),
			// so the rung parenthetical itself stays byte-identical on
			// the happy path.
			if unbacked {
				line += unbackedSuffix
			}
			runs = append(runs, validation.VStr(line))
		}
		tally.add(e)
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
	// The derived refusal histogram closes the run lines: appended AFTER
	// every per-invariant line (one line per invariant, then the tally) and
	// only when an eligible record exists — the per-invariant lines and the
	// key's presence gate are otherwise untouched.
	if line, ok := tally.line(); ok {
		runs = append(runs, validation.VStr(line))
	}
	// Presence-gated: campaigns without a single verification.harness
	// field (every golden campaign) keep the exact historical bytes.
	if len(runs) > 0 {
		out = append(out, KV("harness_runs", validation.VArr(runs...)))
	}
	return validation.VObj(out...), nil
}

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
	h := objAt(objAt(e, "verification"), "harness")
	if h.Kind != validation.Obj {
		return "" // no harness object: no run, nothing to back
	}
	rung := objStr(h, "rung")
	if rung == "" {
		return "" // no rung at all: the sanctioned silent skip
	}
	missing := []string{}
	for _, key := range []string{"kind", "exec"} {
		if objStr(h, key) == "" {
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

// harnessRungBacked returns "" when the invariant's stored harness rung
// is the outcome of the LAST harness_run event for it (events are the
// truth; the slot is the latest bind — if the slot disagrees with the
// newest event, somebody wrote to the slot WITHOUT an event: hand-edit,
// a refused bind whose unwind itself failed, or a version skew).
func harnessRungBacked(events []validation.Value, iid string,
	entry validation.Value) string {
	h := objAt(objAt(entry, "verification"), "harness")
	last := validation.VNull()
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		d := objAt(ev, "data")
		if objStr(d, "invariant") == iid {
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
	slotK, eventK := objAt(h, "bounded_k"), objAt(last, "bounded_k")
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
	slotProof := objAt(h, "proof")
	evDig := objStr(last, "proof_sha256")
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
		want := objStr(h, key)
		got := objStr(last, key)
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
					validation.PyReprStr(objStr(h, "rung")))
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

// pyKind names a JSON value's shape for drift messages (null != 100 is
// the informative case; "Null vs Int" says it).
func pyKind(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "absent/null"
	case validation.Int:
		return fmt.Sprintf("%d", v.I)
	default:
		return validation.CanonCompact(v)
	}
}

// proofDigest mirrors cli.harnessProofDigest (canonical JSON, sha256):
// two packages, one fingerprint — keep byte-identical.
func proofDigest(proof validation.Value) string {
	sum := sha256.Sum256([]byte(validation.CanonCompact(proof)))
	return hex.EncodeToString(sum[:])
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
	h := objAt(objAt(entry, "verification"), "harness")
	last := validation.VNull()
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		d := objAt(ev, "data")
		if objStr(d, "invariant") == iid {
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
	kindStr := objStr(h, "kind")
	kind, known := harness.NormalizeKind(kindStr)
	if !known || kindStr != string(kind) {
		return harnessKindBurn(iid, kindStr, known)
	}
	exec := objStr(last, "exec")
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
	rung := objStr(last, "rung")
	if rung != harness.RungProvedBounded &&
		rung != harness.RungCounterexample {
		return ""
	}
	return fmt.Sprintf("%s: the last harness_run event names exec %s, which "+
		"is neither an EXEC- ledger id nor a REPORT- digest — no bind writes "+
		"that provenance, so the %s rung is not backed", iid,
		validation.PyReprStr(exec), validation.PyReprStr(rung))
}

// harnessScaffoldArtifactBytes reads the T17 scaffold artifact bytes the
// bind hashed and re-rendered: the latest harness_scaffold event for
// HARNESS-<INV>-<kind> names the registered artifact as its ref, and the
// bytes come back through the registry's OWN reader (state.ArtifactBytes,
// which refuses a path whose file no longer hashes to the pinned sha — the
// same r25 F2 discipline recheckRegistryEvidence applies to report bytes).
// why != "" means the bytes could not be obtained, and names what is
// missing (r28b F3 constraint 3: "cannot re-derive" is never a blessing).
func harnessScaffoldArtifactBytes(c *state.Campaign,
	events []validation.Value, iid string,
	kind harness.Kind) (raw []byte, why string) {
	want := "HARNESS-" + iid + "-" + string(kind)
	ref := ""
	for _, ev := range events {
		if objStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if objStr(objAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = objStr(ev, "ref")
	}
	if ref == "" {
		return nil, fmt.Sprintf("no harness_scaffold event names %s", want)
	}
	art, err := c.Artifact(ref)
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s the bind "+
			"hashed is not registered any more", ref)
	}
	raw, err = c.ArtifactBytes(art)
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s cannot be "+
			"re-read the way the row pins it: %v", ref, err)
	}
	return raw, ""
}

// harnessScaffoldBindBytes reads the scaffold bytes the way the BIND reads
// them (cli.harnessScaffoldBytes): the latest harness_scaffold event's ref,
// the registry row's own path, read whole and RAW — no sha re-check, because
// the bind makes none. It is the fallback the unbound arm of section 11 uses
// when the pinned reader (harnessScaffoldArtifactBytes) refused only because
// the FILE no longer hashes to the row's registered sha (r29b F3(c)).
// why != "" names what is missing and means the bind could not read the file
// either.
func harnessScaffoldBindBytes(c *state.Campaign,
	events []validation.Value, iid string,
	kind harness.Kind) (raw []byte, why string) {
	want := "HARNESS-" + iid + "-" + string(kind)
	ref := ""
	for _, ev := range events {
		if objStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if objStr(objAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = objStr(ev, "ref")
	}
	if ref == "" {
		return nil, fmt.Sprintf("no harness_scaffold event names %s", want)
	}
	art, err := c.Artifact(ref)
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s the bind "+
			"hashed is not registered any more", ref)
	}
	raw, err = harness.ArtifactFileBytes(c.Root, objStr(art, "path"))
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s has no readable "+
			"file: %v", ref, err)
	}
	return raw, ""
}

// scaffoldUnavailableBurn is r28b F3 constraint 3 reasoned against the
// bind's own arms: a blessing's hash arm CANNOT be re-derived without the
// scaffold bytes it hashed (they are what the recorded sha256 is compared
// against, and what Validate re-renders), so a record that carries HARNESS
// FILE hash evidence burns as "not backed", naming the key it carries and
// what is missing.
//
// r29b F3(a)(b): the arm asks the REAL question through the bind's own
// predicate — harness.ScaffoldFileHashes, the scaffold-file keys (H.t.sol /
// F.t.sol / INV.mspec, r29b F5), not `len(hashes) > 0`. Every sandbox record
// carries the artifact_hashes stdout/stderr digests, so the old test was true
// for EVERY real record: pruning a normal campaign's scaffold row made this
// burn claim the record "carries recorded harness file hash(es) … bound to"
// bytes it never mentioned, sending the operator to repair the wrong thing.
// A record with no harness-file hash is the UNBOUND arm, and it is not this
// function's question at all — see scaffoldBytesForUnboundArm.
func scaffoldUnavailableBurn(iid, exec, why string,
	rec validation.Value) string {
	if why == "" {
		return ""
	}
	files := harness.ScaffoldFileHashes(rec)
	if len(files) == 0 {
		return ""
	}
	keys := make([]string, 0, len(files))
	for _, f := range files {
		keys = append(keys, validation.PyReprStr(f.Key))
	}
	return fmt.Sprintf("%s: exec %s records a harness-file hash (%s) whose "+
		"scaffold bytes cannot be re-derived (%s) — the bind's hash arm "+
		"compares that recorded sha against exactly those bytes and its "+
		"Validate re-render runs on them, so the rung is not backed", iid,
		exec, strings.Join(keys, ", "), why)
}

// scaffoldBytesForUnboundArm is the scaffold the UNBOUND arm judges
// (r29b F3(c)). When the pinned reader handed bytes back they are returned
// unchanged. Otherwise — and by the time this is reached
// scaffoldUnavailableBurn has already refused every record that carries a
// harness-file hash, so the bind's hash comparison here is vacuous by
// definition — the bind still Validates the scaffold FILE it read from disk
// against the CURRENT claim, and its only reader rule the pinned one lacks is
// the row's sha (which the bind never checks). So read the same file the same
// way and hand the audit the bytes the bind would have judged: a claim that
// drifted away from them is then refused here exactly as the bind refuses it.
//
// When even that read is unobtainable (no harness_scaffold event, no
// registry row, an unreadable file) the arm stays SILENT, deliberately:
// absence is inconclusive — never a blessing, and never a burn. There is no
// decision to reproduce in that world (a bind could not have produced this
// rung either), and burning would torch honest aged campaigns whose scaffold
// row was reconciled away. The hash-carrying shapes, where a recorded sha IS
// evidence this rail cannot compare, burn above.
func scaffoldBytesForUnboundArm(c *state.Campaign,
	events []validation.Value, iid string, kind harness.Kind, scaffold []byte,
	why string) []byte {
	if len(scaffold) != 0 || why == "" {
		return scaffold
	}
	if raw, bwhy := harnessScaffoldBindBytes(c, events, iid, kind); bwhy == "" {
		return raw
	}
	return nil
}

func recheckExecEvidence(c *state.Campaign, events []validation.Value,
	iid string, entry, h, last validation.Value, exec string,
	kind harness.Kind) string {
	// r24 scope law: re-derivation guards the rungs that RECORD CREDIT
	// (proved-bounded, counterexample). An inconclusive rung blesses
	// nothing, and torching its (often old, often pruned) witness dir
	// would punish honesty with noise.
	rung := objStr(last, "rung")
	if rung != harness.RungProvedBounded &&
		rung != harness.RungCounterexample {
		// r25 preemption (critic's sharpest): a forged (slot,event)
		// pair claiming inconclusive with an invented `| next:` advice
		// line feeds the disposition tally — the moment a planner
		// consumes classes, fabricated advice steers the campaign.
		// Re-derive summary+proof digests ONLY when the evidence
		// still exists on disk (an aged-out witness dir stays silent:
		// absence is not proof of a lie), and burn ONLY the
		// over-claim directions (claimed advice the bytes contradict;
		// claimed-absent proof present in the run).
		if kind == harness.MiniCertora {
			return recheckInconclusive(c, events, iid, entry, h, last,
				exec, kind)
		}
		return ""
	}
	if kind != harness.MiniCertora {
		return recheckMapRunEvidence(c, events, iid, entry, last, exec, kind)
	}
	recs, err := state.AllExecs(c)
	if err != nil {
		return fmt.Sprintf("%s: the exec ledger cannot be read (%v)",
			iid, err)
	}
	var rec validation.Value
	for _, e := range recs {
		if objStr(e, "exec_id") == exec {
			rec = e
			break
		}
	}
	if rec.Kind != validation.Obj {
		return fmt.Sprintf("%s: provenance names %s, which the exec "+
			"ledger does not hold — the witness was deleted or never "+
			"existed; the run is unbacked by its own evidence", iid, exec)
	}
	// r29b F2: the BIND's own reader (harness.ReadExecStdout) — its
	// candidate order, its 1MB cap and its truncation semantics. The bare
	// os.ReadFile of <execDir>/stdout.log this arm used to make read the
	// whole file, so a capture over the cap whose duplicated verdict line
	// sat past byte 1,048,576 re-derived "inconclusive (duplicate verdict
	// lines for rule)" over a run the bind had honestly mapped as
	// proved-bounded: the audit burned a fresh bind for reading bytes the
	// bind never read.
	raw, rerr := harness.ReadExecStdout(filepath.Join(c.ExecsDir, exec), rec)
	if rerr != nil {
		return stdoutUnreadableBurn(iid, exec, rerr)
	}
	// r28b F3: the audit re-derives through the SAME decision entry point
	// the bind used, with the SAME arguments — the recorded-hash arm, the
	// Validate re-render of the CURRENT claim and the unbound suffix all
	// live in harness.DecideBound. Calling the kind mapper directly (the
	// r24 shape) reproduced only the last step, so a blessing bound before
	// its claim drifted, or bound to a hash the record has since replaced,
	// audited out clean while a re-bind over the same record + claim
	// refused "scaffold-degraded: …" / "scaffold-bound violation: …".
	scaffold, scaffoldWhy := harnessScaffoldArtifactBytes(c, events, iid,
		harness.MiniCertora)
	if msg := scaffoldUnavailableBurn(iid, exec, scaffoldWhy, rec); msg != "" {
		return msg
	}
	scaffold = scaffoldBytesForUnboundArm(c, events, iid,
		harness.MiniCertora, scaffold, scaffoldWhy)
	inv := harness.InvValue(iid, entry)
	// r28b F2: the exit status comes from the BIND's own reader
	// (harness.RecordExitStatus: absent/null/too-wide -> -2). This arm used
	// to read `es := 0` with no guard, so a chain-valid forged pair over a
	// record whose exit_status was absent or null re-derived an honest
	// PROVEN line as proved-bounded and audited green — absence read as a
	// clean exit. Absence is inconclusive, never a blessing.
	//
	// r33 F1: and the invocation bound comes from the BIND's own reader
	// TOO — harness.RecordInvocationBound(kind, rec). This site (like the
	// two siblings below) passed the KIND-FREE reader, so a record whose
	// command names a real tool other than the rung's kind (a `halmos
	// --fuzz-runs 4000` record bound as --kind forge-fuzz: an honest 4000
	// for forge, a foreign-flag floor for the kind-free parse) was read two
	// ways by the two halves. DecideBound only lets a FLOORING kind-aware
	// re-read override the caller, so the audit's floored k survived and it
	// burned a bind that re-binds byte-for-byte.
	invK := harness.RecordInvocationBound(kind, rec)
	decRung, decSummary, decProof, decBK := harness.DecideBound(
		harness.MiniCertora, inv, raw, rec, scaffold,
		harness.RecordTimedOut(rec), invK, harness.RecordExitStatus(rec),
		harness.MspecRuleName(iid))
	if want := objStr(last, "rung"); decRung != want {
		return fmt.Sprintf("%s: exec %s stdout re-derives rung %s; the "+
			"event claims %s — the mapping did not come from this run's "+
			"bytes (re-derived: %s)", iid, exec,
			validation.PyReprStr(decRung), validation.PyReprStr(want),
			decSummary)
	}
	proof := decProof
	// The slot proof carries the mapper-appended compiler_pin (host
	// provenance, not tool bytes): strip it before comparing to what
	// re-deriving from stdout alone produces.
	stripPin := func(v validation.Value) validation.Value {
		if v.Kind != validation.Obj {
			return v
		}
		var kvs []validation.KV
		for _, kv := range v.O {
			if kv.K != "compiler_pin" {
				kvs = append(kvs, kv)
			}
		}
		return validation.VObj(kvs...)
	}
	if dig := objStr(last, "proof_sha256"); dig != "" {
		slotProof := stripPin(objAt(h, "proof"))
		slotDig := proofDigest(slotProof)
		reD := proofDigest(stripPin(proof))
		// A slot that stored LESS proof than the bytes support is
		// under-reporting (hides witness richness, claims no extra
		// credit) — inconclusive-safe territory, not a lie: skip. The
		// burned directions are slot OVER the bytes (fabricated or
		// inflated subtree) and mismatched non-null pairings.
		slotEmpty := slotProof.Kind == validation.Null
		if !slotEmpty && slotDig != reD {
			return fmt.Sprintf("%s: exec %s stdout re-derives proof sha "+
				"%s; the slot carries %s — the proof subtree is not this "+
				"run's bytes (event pinned %s)", iid, exec, reD[:12],
				slotDig[:12], dig[:12])
		}
	}
	if bkV := objAt(last, "bounded_k"); bkV.Kind == validation.Int {
		have := int64(-1)
		if decBK != nil {
			have = int64(*decBK)
		}
		if have != bkV.I {
			return fmt.Sprintf("%s: exec %s stdout re-derives bounded_k "+
				"%d; the event pins %d — the bound is inflated", iid, exec,
				have, bkV.I)
		}
	}
	return ""
}
func recheckRegistryEvidence(c *state.Campaign, iid string, h,
	last validation.Value, kind harness.Kind, exec string) string {
	// r34 F1: the title is the ATTRIBUTION, and the bind's autoprove door
	// asks for it FIRST — cli.verifyAutoprove's opening check refuses an
	// empty one ("verify --autoprove needs --property <exact title the
	// prover gave the property> — attribution is exact-match by design")
	// before it opens the report, loads links or scans the holder ledger. A
	// report rung whose event carries no title therefore names a property NO
	// BIND CAN WRITE, and nothing downstream may resolve it: an empty
	// property_outcomes[""] entry is not evidence of anything, and this arm
	// used to hand it straight to DecideReport's exact lookup (which found
	// the "" key) while reportProofCollisionBurn's `prop == ""` early return
	// switched the one-proof-one-row rail off — so a chain-valid pair
	// claiming "" audited GREEN with an unqualified blessing line over bytes
	// a fresh bind refuses without ever reading them. Absence is not "no
	// claim" on a report rung: the rung is not backed. The check sits FIRST
	// for the same reason the bind's does — this is the verb's own order.
	if prop := objStr(last, "property"); prop == "" {
		return fmt.Sprintf("%s: the last harness_run event for this report "+
			"rung carries property %s — no bind can write an empty title "+
			"(verify --autoprove refuses one outright: \"needs --property "+
			"<exact title the prover gave the property> — attribution is "+
			"exact-match by design\"), so the rung's proof is attributed to "+
			"no title and it is not backed", iid, validation.PyReprStr(prop))
	}
	dig := objStr(last, "report_sha256")
	if dig == "" {
		// r32b F2: r23's report_sha256 is the pin that makes a report rung
		// checkable at all — the digest names the bytes this bind mapped
		// and the campaign store holds them. The old `return ""` here
		// ("pre-r23 autoprove event; refresh will pin it") was a carve-out
		// in NO doc and reachable by deleting ONE field: no registry
		// lookup happened, no re-derivation ran, and the run still
		// displayed as an UNQUALIFIED blessing ("INV-1: PROVEN-BOUNDED
		// (miniprover, k=4, REPORT-…)") with nothing to say those bytes
		// exist nowhere.
		//
		// There is no carve-out left, and none is needed: this arm is
		// reached only when the event's exec is REPORT-<digest> or the
		// slot kind is the report kind (harnessEvidenceRecheck), so every
		// shape arriving here IS a report run, and cli.verifyAutoprove
		// writes report_sha256 on every event it lands — a report
		// provenance without a digest is a shape no bind produced.
		// Absence is inconclusive, never a blessing.
		return fmt.Sprintf("%s: the last harness_run event names report "+
			"provenance (%s, rung %s) but pins no report_sha256 — the "+
			"bytes it blessed are named nowhere, so the mapping cannot be "+
			"re-derived from them; the rung is not backed", iid,
			validation.PyReprStr(objStr(last, "exec")),
			validation.PyReprStr(objStr(last, "rung")))
	}
	st, err := c.State()
	if err != nil {
		return fmt.Sprintf("%s: registry unreadable (%v)", iid, err)
	}
	var row validation.Value
	for _, a := range objAt(st, "artifacts").A {
		if objStr(a, "sha256") == dig {
			row = a
			break
		}
	}
	if row.Kind != validation.Obj {
		return fmt.Sprintf("%s: no registry artifact holds the report "+
			"bytes the event pins (sha %s) — the evidence named by the "+
			"bind is not in the store (substituted path or quiet "+
			"reconcile)", iid, dig[:12])
	}
	// r25 F2: OWNERSHIP was paperwork; re-DERIVE the decision from the
	// bytes the row holds, through harness.MapReport — the function the
	// mapper itself now runs. A forged (slot,event) pair naming honest
	// registry bytes still has to match what those bytes say.
	raw, rerr := c.ArtifactBytes(row)
	if rerr != nil {
		return fmt.Sprintf("%s: pinned report bytes (%s) cannot be "+
			"re-read from the store (%v) — uncheckable is not backed",
			iid, dig[:12], rerr)
	}
	rep, perr := validation.ParseOrdered(raw)
	if perr != nil || rep.Kind != validation.Obj {
		return fmt.Sprintf("%s: the pinned report bytes no longer parse "+
			"(%v) — the store does not hold what the bind named", iid,
			perr)
	}
	// r32b F1: the SAME decision entry point the bind runs, over the SAME
	// inputs — the pinned copy's bytes, the property name the event binds,
	// and the flags inside those bytes. harness.DecideReport owns the five
	// run-level gates (publish_problems' shape and emptiness, published,
	// review_error, the review_findings SHAPE, SUSPECT attribution), the
	// EXACT property lookup (ReportProperty — the bind's own rule, no fold
	// fallback) and the typed bound, and it ends in harness.MapReport.
	// Before this the audit re-derived only rung/summary/bounded_k, so a
	// chain-valid report copy whose ONLY difference was a SUSPECT finding
	// (or published:false) audited green over bytes a fresh bind refuses
	// with exit 2.
	dec := harness.DecideReport(rep, objStr(last, "property"))
	if dec.Gate != harness.GateNone {
		return fmt.Sprintf("%s: the pinned report bytes fail the bind's "+
			"%s gate (%s) — a fresh bind of these very bytes is refused, "+
			"so no mapper produced this event; the rung is not backed",
			iid, dec.Gate, strings.TrimRight(dec.Refusal, "\n"))
	}
	rung, summary, bk := dec.Rung, dec.Summary, dec.BoundedK
	if want := objStr(last, "rung"); want != rung {
		return fmt.Sprintf("%s: the pinned report re-derives to rung "+
			"%s; the event claims %s — the mapping did not come from "+
			"these bytes", iid, validation.PyReprStr(rung),
			validation.PyReprStr(want))
	}
	if want := objStr(last, "summary"); want != summary {
		return fmt.Sprintf("%s: the pinned report re-derives summary "+
			"%s; the event carries %s", iid,
			validation.PyReprStr(summary), validation.PyReprStr(want))
	}
	if bk == nil {
		if v := objAt(last, "bounded_k"); v.Kind == validation.Int {
			return fmt.Sprintf("%s: the pinned report states no bound; "+
				"the event pins bounded_k %d — inflated", iid, v.I)
		}
		// r34 F1's ADJACENT ARM: the same off-switch one field over — a
		// BLANK bound. For a property whose rollup is bound UNSTATED
		// (MapReport returns a nil bound) the bind writes bounded_k null and
		// NO proof sidecar, and the arm above found "nothing to compare" in
		// both fields. But the DISPLAY line's k is harnessBoundK(h): the
		// slot's bounded_k when it is an integer, ELSE the slot proof's
		// bounds.loop_bound — the minicertora/scaffold fallback. A chain-valid
		// forgery that adds a proof subtree to the slot and re-lands the
		// matching harness_run event (proof_sha256 over those very bytes,
		// bounded_k still null) therefore printed
		// "INV-3: PROVEN-BOUNDED (miniprover, k=999999, REPORT-…)" over a
		// pinned report that states no bound at all, and audited GREEN: no
		// mapper wrote a bound for these bytes, so the k the line renders is
		// a number the evidence denies. The mirror direction (a derived bound
		// the line does not render) is already closed by the event arm above
		// plus harnessRungBacked's slot/event kind+value comparison.
		if shown, ok := harnessBoundK(h); ok {
			return fmt.Sprintf("%s: the pinned report states no bound (the "+
				"rollup is bound UNSTATED) and the event pins none, but the "+
				"stored harness slot renders k=%s from its proof subtree — a "+
				"bound these bytes never stated; the rung is not backed", iid,
				shown)
		}
	} else if v := objAt(last, "bounded_k"); v.Kind != validation.Int ||
		v.I != int64(*bk) {
		return fmt.Sprintf("%s: the pinned report derives bounded_k "+
			"%d; the event carries a different bound", iid, *bk)
	}
	// ------------------------------------------------------------------
	// r33 F4/F5: the PROVENANCE the bind would have written for these bytes.
	//
	// Everything above re-derives the MAPPING from the pinned report bytes;
	// none of it reads the rung's own (kind, exec) pair, and three shapes no
	// bind writes rode that gap to a green audit with an unqualified
	// blessing line:
	//
	//	(a) exec = an EXEC- id the campaign does not hold. The bind checks
	//	    every --exec it is handed against the exec ledger
	//	    (cli.verifyAutoprove -> harnessExecRecord) and refuses an unknown
	//	    one with exit 2 ("no exec … in this campaign's exec ledger"); a
	//	    forged slot+event pair carrying "EXEC-99999999-nope" printed that
	//	    label as the witness of a rung whose run does not exist.
	//	(b) exec = a REPORT-<digest12> label that does not name the pinned
	//	    bytes. The bind computes the label FROM the digest it mapped
	//	    (harness.ReportExecLabel), so a label free to disagree with the
	//	    pin is printed provenance no run had — the display line reads
	//	    "…, REPORT-000000000000)" over a rung re-derived from
	//	    89889f8cf360….
	//	(c) a REPORT- provenance wearing an exec-shaped kind (r33 F5): the
	//	    report-bound bind writes harness.ReportKind, and the mapper this
	//	    arm runs is MapReport over the pinned bytes, so a rung claiming
	//	    halmos/forge-fuzz/minicertora while pinned to report bytes names
	//	    a captured stdout that was never read.
	//
	// (b) and (c) are harness.ReportProvenanceReason — the bind's own label
	// rule and its own kind, one home. (a) is the bind's own ledger lookup.
	//
	// The order is deliberate and is what keeps r29b F1(a) honest: the
	// digest/registry/bytes/gate/mapping checks above stay FIRST, so a report
	// row that is missing from the store still burns with the sentence that
	// shape is pinned to ("no registry artifact holds the report bytes the
	// event pins"), even when the rung also wears a scaffold kind.
	// ------------------------------------------------------------------
	if why := harness.ReportProvenanceReason(kind, exec, dig); why != "" {
		return fmt.Sprintf("%s: %s", iid, why)
	}
	if !strings.HasPrefix(exec, "REPORT-") {
		recs, lerr := state.AllExecs(c)
		if lerr != nil {
			return fmt.Sprintf("%s: the exec ledger cannot be read (%v) — "+
				"the provenance %s it names cannot be checked", iid, lerr,
				validation.PyReprStr(exec))
		}
		held := false
		for _, e := range recs {
			if objStr(e, "exec_id") == exec {
				held = true
				break
			}
		}
		if !held {
			return fmt.Sprintf("%s: provenance names %s, which the exec "+
				"ledger does not hold — the bind verifies every --exec it "+
				"writes against that ledger (its own refusal is \"no exec "+
				"… in this campaign's exec ledger\"), so no bind wrote this "+
				"label and the witness it prints does not exist; the rung "+
				"is not backed", iid, validation.PyReprStr(exec))
		}
	}
	return ""
}

// reportProofCollisionBurn is r33 F2: ONE PROOF, ONE ROW, for the report
// rungs — the audit's re-derivation of the law the bind enforces in
// cli.verifyAutoprove (autoprovePropertyHolder + the caller's
// `holder != a.autoprove` refusal: "one property's proof binds one
// invariant").
//
// The bind's law, READ OFF ITS OWN CODE AND OBSERVED (not inferred):
// autoprovePropertyHolder scans the harness_run events in sequence for the
// FIRST event whose `property` folds equal to the property being bound
// (cli.autoproveSameName -> harness.SamePropertyName: case and edge
// whitespace fold) and the verb refuses with exit 2 when that event belongs
// to a DIFFERENT invariant:
//
//	verify --autoprove: property 'p1' was already bound to INV-1
//	(REPORT-89889f8cf360) — one property's proof binds one invariant;
//	give the second invariant its OWN property (digest churn is not a new
//	proof)
//
// Note what that scan does NOT look at: the report PIN. It filters on the
// property alone, so the same property title over a DIFFERENT report is
// still "already bound" — measured, not assumed, in
// internal/cli/zz_r33_test.go's TestR33DuplicateControlsStayGreen, where the
// cross-pin bind is refused with the sentence above. An audit rail keyed on
// (pin, property) would therefore bless a duplicate attribution the bind
// refuses: the same forgery as F2's repro with one byte of the report
// changed. So this rail keys on the PROPERTY, exactly as the bind does.
//
// Within that key, the FIRST event (in sequence) keeps its rung; every LATER
// event claiming the same folded property for a DIFFERENT invariant burns,
// naming the collision and the row that bound it first. Three deliberate
// properties of the reading:
//
//   - the fold is harness.SamePropertyName, the bind's own comparison — the
//     two copies of it were collapsed into that one function by this same
//     finding, so a report keyed "p1" whose second row names "P1" collides
//     here exactly as the bind's holder scan collides;
//   - the SAME invariant re-claiming the property is a REFRESH, not a
//     collision: the bind's holder scan returns the first holder and refuses
//     only a DIFFERENT one, so an invariant re-binding its own proof (a
//     newer report for the same property — the re-bind the verb explicitly
//     discloses with a warning — or a byte-identical re-bind) stays green;
//   - an event with no `property` field is not a CLAIMANT — it holds no
//     title, so it can never be named as the row that bound one (the
//     exec-bound payload carries none, and the holder must be a row that
//     actually stated the title);
//   - r34 F1: but a REPORT rung with a blank or absent title is NOT "no
//     claim" — it is a title no bind can write (cli.verifyAutoprove's first
//     check refuses an empty --property before it reads the report), so it
//     is a claim like any other and the rail below runs for it. The opening
//     `prop == ""` early return was an OFF-SWITCH: two rows claiming "" over
//     one pinned proof both displayed an unqualified blessing (and
//     recheckRegistryEvidence then resolved the report's
//     property_outcomes[""] entry, which no bind ever asked for). The
//     blank title's own burn ("no bind can write …", in
//     recheckRegistryEvidence) and this rail therefore both fire, and no
//     pair of rows can both display a blessing. The claimant-side blank stays
//     a non-claimant deliberately: accusing the exec-bound row that has no
//     property field of holding the blank title would put a false
//     attribution in the audit's problems. Anything ELSE is a claim, pin or
//     no pin: the bind's scan reads the property and nothing else.
//
// "" when the first claimant IS this invariant (its own rung is a refresh or
// a collision-free claim).
func reportProofCollisionBurn(events []validation.Value, iid string,
	last validation.Value) string {
	prop := objStr(last, "property")
	firstInv, firstExec, firstPin := "", "", ""
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		d := objAt(ev, "data")
		// r34 F1: a claimant must CARRY a title. objStr alone reads an
		// absent/non-string field as "", which would let an exec-bound event
		// (no property field at all) be named as the holder of the blank
		// title — a holder that never claimed it. For every non-blank title
		// this is the same claimant set as before: "" folds equal to no
		// non-blank title.
		if objAt(d, "property").Kind != validation.Str {
			continue
		}
		if !harness.SamePropertyName(objStr(d, "property"), prop) {
			continue
		}
		inv := objStr(d, "invariant")
		if inv == "" {
			continue
		}
		if firstInv == "" {
			firstInv, firstExec = inv, objStr(d, "exec")
			firstPin = objStr(d, "report_sha256")
		}
	}
	if firstInv == "" || firstInv == iid {
		return ""
	}
	pin := firstPin
	if len(pin) > 12 {
		pin = pin[:12]
	}
	if pin == "" {
		pin = "-"
	}
	return fmt.Sprintf("%s: report property %s is already bound to %s "+
		"(%s, report %s) — one property's proof binds one invariant, and "+
		"the first claimant keeps its rung; this row's rung is not backed",
		iid, validation.PyReprStr(prop), firstInv, firstExec, pin)
}

// autoproveProp was r26 F1's EXACT-first resolution with a single
// fold-equal fallback. r32b F1 deleted it: the fallback is a lookup the
// bind never makes (cli.fieldOf is exact-only), so a forged event naming
// "P1" for a report keyed "p1" re-derived a mapping the bind refuses. The
// one lookup now lives in harness.ReportProperty, called by
// harness.DecideReport, which both the bind and this section run.

// recheckMapRunEvidence extends the read-time law to halmos/forge-fuzz
// (r25 F1: the kind-skip arm was E5's open door — a chain-valid forged
// pair rendered `halmos, k=100` over a stdout whose marker said k=7,
// and `rung=counterexample` over a PASS output, audit-green). Same
// discipline, same entry point: the bind's own decision function
// (harness.DecideBound) over the stored bytes, the record's own
// timedOut/exit status/invocation bound and the scaffold artifact bytes,
// which must reproduce the claimed rung — and a proved-bounded claim must
// reproduce bounded_k. r28b F3 closed the remaining hole here too: this arm
// used to call MapRun directly, so a halmos blessing whose recorded H.t.sol
// hash had since been replaced by a foreign sha (or whose scaffold artifact
// was pruned) re-derived proved-bounded and audited green while the bind
// would have refused it.
func recheckMapRunEvidence(c *state.Campaign, events []validation.Value,
	iid string, entry, last validation.Value, exec string,
	kind harness.Kind) string {
	if kind != harness.Halmos && kind != harness.ForgeFuzz {
		// r29b F1: this was the skip door — `return ""` for every kind that
		// is not halmos/forge-fuzz, with a comment claiming harnessRunLine
		// renders no line for an unknown kind (it renders one for any
		// non-empty kind). Only the two MapRun kinds can legitimately arrive
		// here (harnessEvidenceRecheck resolves the kind first), so anything
		// else is a spelling no mapper implements and must burn by name.
		return fmt.Sprintf("%s: stored harness kind %s is not one of the "+
			"kinds MapRun implements (halmos, forge-fuzz) — no mapper "+
			"produced this rung, so it is not backed", iid,
			validation.PyReprStr(string(kind)))
	}
	recs, err := state.AllExecs(c)
	if err != nil {
		return fmt.Sprintf("%s: the exec ledger cannot be read (%v)",
			iid, err)
	}
	var rec validation.Value
	for _, e := range recs {
		if objStr(e, "exec_id") == exec {
			rec = e
			break
		}
	}
	if rec.Kind != validation.Obj {
		return fmt.Sprintf("%s: provenance names %s, which the exec "+
			"ledger does not hold — the witness was deleted or never "+
			"existed; the run is unbacked by its own evidence", iid, exec)
	}
	// r29b F2: the bind's own reader, so both halves map the same bytes at
	// the same length (see recheckExecEvidence).
	raw, rerr := harness.ReadExecStdout(filepath.Join(c.ExecsDir, exec), rec)
	if rerr != nil {
		return stdoutUnreadableBurn(iid, exec, rerr)
	}
	scaffold, scaffoldWhy := harnessScaffoldArtifactBytes(c, events, iid,
		kind)
	if msg := scaffoldUnavailableBurn(iid, exec, scaffoldWhy, rec); msg != "" {
		return msg
	}
	scaffold = scaffoldBytesForUnboundArm(c, events, iid, kind, scaffold,
		scaffoldWhy)
	// r33 F1: the KIND-AWARE bound reader, the same one the bind calls
	// (harness.RecordInvocationBound — see recheckExecEvidence).
	invK := harness.RecordInvocationBound(kind, rec)
	rung, decSummary, _, decBK := harness.DecideBound(kind,
		harness.InvValue(iid, entry), raw, rec, scaffold,
		harness.RecordTimedOut(rec), invK, harness.RecordExitStatus(rec),
		"")
	if want := objStr(last, "rung"); rung != want {
		return fmt.Sprintf("%s: exec %s stdout re-derives rung %s; the "+
			"event claims %s — the mapping did not come from this run's "+
			"bytes (re-derived: %s)", iid, exec,
			validation.PyReprStr(rung), validation.PyReprStr(want),
			decSummary)
	}
	if rung == harness.RungProvedBounded {
		if bkV := objAt(last, "bounded_k"); bkV.Kind == validation.Int {
			have := int64(-1)
			if decBK != nil {
				have = int64(*decBK)
			}
			if have != bkV.I {
				return fmt.Sprintf("%s: exec %s stdout re-derives "+
					"bounded_k %d; the event pins %d — the bound is "+
					"inflated", iid, exec, have, bkV.I)
			}
		}
	}
	return ""
}

func recheckInconclusive(c *state.Campaign, events []validation.Value,
	iid string, entry, h, last validation.Value, exec string,
	kind harness.Kind) string {
	recs, err := state.AllExecs(c)
	if err != nil {
		// r44a: the silence below ("aged-out witness: nothing to re-derive
		// against") is reserved for a witness that is genuinely ABSENT from a
		// store that WAS listed. A ledger that could not be listed is a
		// refusal, and folding it into the absent case would let this arm
		// pass over evidence it never read. Same text as the sibling arm in
		// recheckExecEvidence: the rung is named and burned.
		return fmt.Sprintf("%s: the exec ledger cannot be read (%v)", iid, err)
	}
	var rec validation.Value
	for _, e := range recs {
		if objStr(e, "exec_id") == exec {
			rec = e
			break
		}
	}
	if rec.Kind != validation.Obj {
		return "" // aged-out witness: nothing to re-derive against
	}
	// r29b F2: the bind's own reader (candidate order and 1MB cap included),
	// so a decoration the mapper drew from the capped bytes is not compared
	// against a longer file.
	//
	// r44b P3-b: this arm used to `return ""` on EVERY read failure, while
	// the two sibling arms above refuse with stdoutUnreadableBurn. The
	// aged-out silence belongs to the witness that is genuinely ABSENT from
	// a store that was listed (ErrNoCapturedStdout, or a capture the record
	// names and prunes — the r24 scope law: torching an old, pruned witness
	// dir would punish honesty with noise); a capture that is PRESENT and
	// cannot be READ (EACCES, ENOTDIR, EIO) is a refusal, not absence, and
	// folding the two together let a decorated inconclusive rung stand over
	// bytes this audit never read. Only stdoutAbsent folds.
	raw, rerr := harness.ReadExecStdout(filepath.Join(c.ExecsDir, exec), rec)
	if rerr != nil {
		if !stdoutAbsent(rerr) {
			return stdoutUnreadableBurn(iid, exec, rerr)
		}
		return "" // aged-out witness: nothing to re-derive against
	}
	es := harness.RecordExitStatus(rec)
	// Same entry point as the bind (r27 F1, r28b F3): the decision —
	// invocation floor, recorded-hash arm, Validate re-render, unbound
	// suffix — is harness.DecideBound's, so an inconclusive claim is
	// re-derived from the same bytes through the same arms. A refusal-arm
	// summary ("scaffold-degraded: …", "scaffold-bound violation: …",
	// "aborted: …") is NOT an "inconclusive" mapping, and an inconclusive
	// rung blesses nothing: the guard below skips it (modesty — the
	// scope law above), so missing scaffold bytes can never burn an
	// honest inconclusive bind here.
	// r33 F1: the KIND-AWARE bound reader — this function is reached only
	// for kind == minicertora (recheckExecEvidence's dispatch), and the bind
	// reads the same record with harness.RecordInvocationBound(kind, rec).
	// The kind-free reader this used to call disagreed with the bind about
	// any command naming another tool, which is the F1 divergence.
	invK := harness.RecordInvocationBound(kind, rec)
	scaffold, _ := harnessScaffoldArtifactBytes(c, events, iid,
		harness.MiniCertora)
	_, sum, _, _ := harness.DecideBound(kind,
		harness.InvValue(iid, entry), raw, rec, scaffold,
		harness.RecordTimedOut(rec), invK, es, harness.MspecRuleName(iid))
	if !strings.HasPrefix(sum, "inconclusive") {
		return "" // bytes bless MORE than the claim: modesty, never a
		// lie — the pair under-claims and the ledger stays honest.
	}
	// Compare DISPOSITION CLASSES, not bytes: the mapper legitimately
	// decorates stored summaries (the "(unbound: …)" suffix the unbound arm
	// appends, its own "no clean completion" timeout wording), and those are
	// transport/shape differences, not different advice. Disposition() is
	// the canonical classifier the tally itself reads — comparing classes is
	// the right equality for this rail, and the exact-text version (r25
	// first cut) would have burned honest decorated binds.
	wantCls, _, wantOK := harness.Disposition(objStr(last, "summary"))
	gotCls, _, gotOK := harness.Disposition(sum)
	if !wantOK {
		return "" // the pair renders no advice: nothing to fabricate
	}
	if harness.RecordTimedOut(rec) && gotCls == harness.EscalateRuntime &&
		wantCls != harness.EscalateRuntime {
		// A run that never completed, whose bytes re-derive the runtime
		// floor: any OTHER named class is fabricated over a process that
		// was killed (by law its partial bytes map to no verdict).
		//
		// r32 F3: the arm keys on the class the BYTES re-derive, not on
		// the timeout alone. A flooring invocation bound floors on the
		// timeout path too (same predicate as everywhere else), so a
		// timed-out run of a degenerate command re-derives
		// `degenerate-bound` and its stored pair may legitimately carry
		// that class — the old arm burned exactly that honest pair while
		// the generic comparison below already catches any real
		// divergence.
		return fmt.Sprintf("%s: exec %s never completed (exit %d) "+
			"and its bytes re-derive the runtime floor; the bound "+
			"pair claims advice class %q — a disposition no run of "+
			"these bytes can carry", iid, exec, es, wantCls)
	}
	if !gotOK {
		// No named disposition in the bytes (plumbing floor), yet the
		// pair claims one: invented campaign-steering advice.
		return fmt.Sprintf("%s: exec %s stdout re-derives no named "+
			"disposition (%s); the bound pair claims advice class %q "+
			"— fabricated next-step text steers the tally", iid, exec,
			validation.PyReprStr(sum), wantCls)
	}
	if gotCls != wantCls {
		return fmt.Sprintf("%s: exec %s stdout re-derives disposition "+
			"%q; the bound pair claims %q — fabricated next-step text "+
			"steers the tally", iid, exec, gotCls, wantCls)
	}
	return ""
}
