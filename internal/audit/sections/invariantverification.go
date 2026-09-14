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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

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
		if line, ok := harnessRunLine(iid, e); ok {
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
	exec := objStr(last, "exec")
	switch {
	case strings.HasPrefix(exec, "EXEC-"):
		return recheckExecEvidence(c, events, iid, entry, h, last, exec)
	case strings.HasPrefix(exec, "REPORT-"):
		return recheckRegistryEvidence(c, iid, last)
	}
	return ""
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

// scaffoldUnavailableBurn is r28b F3 constraint 3 reasoned against the
// bind's own arms: a blessing's hash arm CANNOT be re-derived without the
// scaffold bytes it hashed (they are what the recorded sha256 is compared
// against, and what Validate re-renders), so a record that carries hash
// evidence burns as "not backed", naming what is missing. The UNBOUND arm
// (no hash evidence at all) needs no scaffold bytes for its MAPPING — its
// hash comparison is vacuous and the rung on record proves the bind's own
// Validate passed at bind time — so it keeps the honest behaviour and
// DecideBound proceeds without the re-render (see harness.DecideBound).
// "" means "this shape may proceed".
func scaffoldUnavailableBurn(iid, exec, why string,
	rec validation.Value) string {
	if why == "" {
		return ""
	}
	hashes, harnessNamed := harness.RecordedHashes(rec)
	if len(hashes) == 0 && !harnessNamed {
		return ""
	}
	return fmt.Sprintf("%s: exec %s carries recorded harness file hash(es), "+
		"but the scaffold bytes they were bound to cannot be re-derived "+
		"(%s) — the bind's hash arm and its Validate re-render both run "+
		"against those bytes, so the rung is not backed", iid, exec, why)
}

func recheckExecEvidence(c *state.Campaign, events []validation.Value,
	iid string, entry, h, last validation.Value, exec string) string {
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
		if objStr(h, "kind") == "minicertora" {
			return recheckInconclusive(c, events, iid, entry, h, last, exec)
		}
		return ""
	}
	if kind := objStr(h, "kind"); kind != "minicertora" {
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
	// Same law as the mapper (r13): the canonical capture path wins.
	raw, rerr := os.ReadFile(filepath.Join(c.ExecsDir, exec,
		"stdout.log"))
	if rerr != nil {
		return fmt.Sprintf("%s: exec %s stdout unreadable (%v) — the "+
			"evidence behind the rung cannot be re-checked", iid, exec,
			rerr)
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
	inv := harness.InvValue(iid, entry)
	// r28b F2: the exit status comes from the BIND's own reader
	// (harness.RecordExitStatus: absent/null/too-wide -> -2). This arm used
	// to read `es := 0` with no guard, so a chain-valid forged pair over a
	// record whose exit_status was absent or null re-derived an honest
	// PROVEN line as proved-bounded and audited green — absence read as a
	// clean exit. Absence is inconclusive, never a blessing.
	invK := harness.InvocationBound(harness.RecordCommand(rec))
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
func recheckRegistryEvidence(c *state.Campaign, iid string,
	last validation.Value) string {
	dig := objStr(last, "report_sha256")
	if dig == "" {
		return "" // pre-r23 autoprove event; refresh will pin it
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
	prop, why := autoproveProp(rep, objStr(last, "property"))
	if why != "" {
		return fmt.Sprintf("%s: %s", iid, why)
	}
	if prop.Kind != validation.Obj {
		return fmt.Sprintf("%s: the pinned report does not attempt the "+
			"property the event binds (%s) — provenance and evidence "+
			"disagree", iid, validation.PyReprStr(
			objStr(last, "property")))
	}
	k, kStated, kOK, _ := harness.BoundFromFlags(objAt(rep, "flags"))
	if !kOK {
		return fmt.Sprintf("%s: the pinned report carries a degenerate "+
			"bound the mapper would refuse — those bytes cannot have "+
			"produced this event", iid)
	}
	rung, summary, bk := harness.MapReport(objStr(prop, "outcome"),
		objAt(prop, "per_rule"), k, kStated)
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
	} else if v := objAt(last, "bounded_k"); v.Kind != validation.Int ||
		v.I != int64(*bk) {
		return fmt.Sprintf("%s: the pinned report derives bounded_k "+
			"%d; the event carries a different bound", iid, *bk)
	}
	return ""
}

// autoproveProp resolves the bound property the way the BIND does:
// cli.fieldOf is an EXACT key lookup, so an exact hit wins outright.
// The fold fallback survives only for a SINGLE fold-equal key (legacy
// spelling); a report carrying several fold-equal keys and no exact hit
// pins no attributable truth, and the auditor must refuse rather than
// pick — r26 F1: the original fold-FIRST-HIT read a different truth
// than the bind had and burned an honest rung (the very
// bind==audit-derivation claim r25 F2 made). Returns a refusal reason
// when the property cannot be attributed at all.
func autoproveProp(rep validation.Value, name string) (validation.Value,
	string) {
	po := objAt(rep, "property_outcomes")
	if po.Kind != validation.Obj {
		return validation.VNull(), ""
	}
	for _, kv := range po.O {
		if kv.K == name {
			return kv.V, ""
		}
	}
	var hit validation.Value
	n := 0
	for _, kv := range po.O {
		if strings.EqualFold(strings.TrimSpace(kv.K),
			strings.TrimSpace(name)) {
			hit = kv.V
			n++
		}
	}
	if n > 1 {
		return validation.VNull(), fmt.Sprintf("the pinned report carries "+
			"%d fold-equal spellings of the bound property %s and no "+
			"exact key — no single truth is attributable (the bind is "+
			"exact-match only, so this event cannot be reproduced from "+
			"these bytes)", n, validation.PyReprStr(name))
	}
	return hit, ""
}

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
	iid string, entry, last validation.Value, exec, kind string) string {
	k := harness.Kind(kind)
	if k != harness.Halmos && k != harness.ForgeFuzz {
		return "" // unknown kinds render no harness_runs line anyway
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
	raw, rerr := os.ReadFile(filepath.Join(c.ExecsDir, exec,
		"stdout.log"))
	if rerr != nil {
		return fmt.Sprintf("%s: exec %s stdout unreadable (%v) — the "+
			"evidence behind the rung cannot be re-checked", iid, exec,
			rerr)
	}
	scaffold, scaffoldWhy := harnessScaffoldArtifactBytes(c, events, iid, k)
	if msg := scaffoldUnavailableBurn(iid, exec, scaffoldWhy, rec); msg != "" {
		return msg
	}
	invK := harness.InvocationBound(harness.RecordCommand(rec))
	rung, decSummary, _, decBK := harness.DecideBound(k,
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
	iid string, entry, h, last validation.Value, exec string) string {
	recs, err := state.AllExecs(c)
	if err != nil {
		return ""
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
	raw, rerr := os.ReadFile(filepath.Join(c.ExecsDir, exec,
		"stdout.log"))
	if rerr != nil {
		return ""
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
	invK := harness.InvocationBound(harness.RecordCommand(rec))
	scaffold, _ := harnessScaffoldArtifactBytes(c, events, iid,
		harness.MiniCertora)
	_, sum, _, _ := harness.DecideBound(harness.MiniCertora,
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
	if harness.RecordTimedOut(rec) {
		// A run that never completed can only be the runtime floor: any
		// OTHER named class is fabricated over a process that was
		// killed (by law its partial bytes map to no verdict).
		if wantCls != harness.EscalateRuntime {
			return fmt.Sprintf("%s: exec %s never completed (exit %d) "+
				"and its bytes re-derive the runtime floor; the bound "+
				"pair claims advice class %q — a disposition no run of "+
				"these bytes can carry", iid, exec, es, wantCls)
		}
		return ""
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
