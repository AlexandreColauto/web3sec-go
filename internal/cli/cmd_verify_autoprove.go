// cmd_verify_autoprove: `webv2 verify <C> --autoprove INV-x --property
// TITLE --report <run>/reports/report.json [--exec EXEC-x]`.
//
// The Phase B mapper of docs/MINIPROVER_INTEGRATION.md §5: MiniProver
// (the auto-prover) drives MiniCertora to author+verify a whole property
// set; this verb consumes the run's machine artifact — reports/report.json
// — and binds the resulting rung to one invariant of the campaign ledger.
//
// Attribution law mirrors the minicertora mapper: EXACT property-title
// match, refusal otherwise (prover titles are agent-authored; guessing a
// binding would attribute one property's proof to another's ledger row).
// Exit codes of the prover are tripwires ONLY — per §3 of the guide,
// verdict authority is report.json. Here, authority is the property's
// own rollup outcome, which the prover computes worst-first.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// autoproveReport is what we trust from the file, kept small on purpose.
//
// r33 F3: the schema_version family this build speaks now lives on the ONE
// decision (harness.ReportSchemaMajor, read by harness.DecideReportSchema)
// instead of here — the verb's door and the audit's re-derivation must
// refuse the same report in the same words, and a constant only one of them
// can see is exactly how a "2.0" report got blessed by section 11.

// verifyAutoprove is cmd_verify's --autoprove branch.
// AutoproveSwapSeam, when armed by a test, runs between parse and the
// pre-bind recheck — the deterministic stand-in for an adversary racing
// a write onto the report path (r23 swap rail).
var AutoproveSwapSeam func()

func verifyAutoprove(c *state.Campaign, a *verifyArgs, r *Runner) error {
	if a.property == "" {
		return t14ExitErr(2,
			"verify --autoprove needs --property <exact title the prover "+
				"gave the property> — attribution is exact-match by "+
				"design (property titles are agent-authored; a guessed "+
				"binding attributes one property's proof to another)\n")
	}
	if a.report == "" {
		return t14ExitErr(2,
			"verify --autoprove needs --report PATH (the run's "+
				"reports/report.json)\n")
	}
	raw, err := os.ReadFile(a.report)
	if err != nil {
		return t14ExitErr(2, "verify --autoprove cannot read the report: %v\n",
			err)
	}
	rep, perr := validation.ParseOrdered(raw)
	if perr != nil || rep.Kind != validation.Obj {
		return t14ExitErr(2, "verify --autoprove: %s does not parse as one "+
			"JSON object — reports/report.json is the machine contract; "+
			"the run directory or a tampered copy is not\n", a.report)
	}
	digest := validation.Sha256Hex(raw)
	// r33 F3: the schema gate is harness.DecideReportSchema — the FIRST
	// gate of the one shared decision (harness.DecideReport), asked here so
	// that this verb refuses a report it cannot read BEFORE it loads links,
	// scans the property-holder ledger or touches the exec ledger (its
	// historical position, and the position its refusal bytes are pinned
	// in). The sentence and the state it names come from the gate, so the
	// audit's re-derivation of a pinned copy refuses in the same words;
	// before this the gate existed only here and section 11 blessed a
	// report whose schema_version was "2.0" or absent.
	if dec := harness.DecideReportSchema(rep); dec.Gate != harness.GateNone {
		return t14ExitErr(2, "verify --autoprove: %s", dec.Refusal)
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return err
	}
	entry, found := harnessInvEntry(links, a.autoprove)
	if !found {
		return t14ExitErr(2, "verify: unknown invariant %s\n",
			validation.PyReprStr(a.autoprove))
	}
	// r20 F9: a proof is a property's, and a property proves ONE
	// invariant — binding the same (report, property) to a second
	// ledger row would duplicate credit for one proof (the double-count
	// the dedup law refuses everywhere else). Scan the event ledger
	// (not display state): the claim must not be laundered by a later
	// overwrite of the first binding.
	// r21 F3: the rail keys on the PROPERTY TITLE, not (digest,property):
	// a trailing newline churned the sha and re-registered the same
	// proof for a second invariant clean. A property is a named claim —
	// the name is the identity; the digest is F10's freshness concern.
	if holder, first := autoprovePropertyHolder(c, a.property); holder != "" && holder != a.autoprove {
		return t14ExitErr(2, "verify --autoprove: property %s was already "+
			"bound to %s (%s) — one property's proof binds one invariant; "+
			"give the second invariant its OWN property (digest churn is "+
			"not a new proof)\n",
			validation.PyReprStr(a.property), holder, first)
	}
	exec := a.execID
	if exec != "" {
		// r20 F7: a provenance row naming a nonexistent EXEC is a
		// fabricated witness — the same harnessExecRecord check the
		// minicertora mapper refuses with.
		if _, _, eerr := harnessExecRecord(c, exec); eerr != nil {
			return eerr
		}
	}
	if exec == "" {
		// No sandbox EXEC wrapped this report: the digest identifies
		// what was mapped, and says so — an honest "report-only"
		// provenance row, not a fabricated EXEC id.
		//
		// r33 F4(b): the label rule is harness.ReportExecLabel, the ONE
		// home — section 11 re-derives the label from the pin with the
		// same function, so a forged "REPORT-000000000000" over a
		// different digest burns instead of printing itself as the
		// witness.
		exec = harness.ReportExecLabel(digest)
	}
	// The run-level gates FIRST: a rollup over a run the prover itself
	// refuses to publish is not evidence of anything.
	//
	// r19 P2 / r20 F6 / r22 F2 / r22 F5 / r24 F3 / r25 F2 — and, since
	// r32b F1, ALL FIVE GATES PLUS THE EXACT PROPERTY LOOKUP AND THE TYPED
	// BOUND live in harness.DecideReport, the SAME function section 11 now
	// re-derives from the pinned copy's bytes with the property name the
	// event binds. They used to exist only here, so the audit blessed a
	// report rung (a SUSPECT finding, published:false) that a fresh bind of
	// those very bytes refuses. One implementation, one sentence: the
	// Refusal is this verb's own text, byte for byte.
	dec := harness.DecideReport(rep, a.property)
	if dec.Gate != harness.GateNone {
		return t14ExitErr(2, "verify --autoprove: %s", dec.Refusal)
	}
	rung, summary, bk := dec.Rung, dec.Summary, dec.BoundedK
	if AutoproveSwapSeam != nil {
		AutoproveSwapSeam() // test-only: write the file post-parse
	}
	// r23: the file was read at parse time; anything changing it between
	// then and the bind makes the event's report_sha256 a name for bytes
	// the registry never hashed. Refuse mid-run swaps BEFORE the bind —
	// nothing to unwind, the re-run maps whatever is current.
	if cur, rerr := os.ReadFile(a.report); rerr != nil ||
		validation.Sha256Hex(cur) != digest {
		return t14ExitErr(2, "verify --autoprove: the report changed on "+
			"disk while being mapped (parse-time sha %s, now different) — "+
			"a bind must name the exact bytes it read; re-run against the "+
			"current file\n", digest[:12])
	}
	// proof sidecar is minicertora-only BY SCHEMA ("ABSENT for other
	// kinds") — the report itself is registered as the artifact instead:
	// its hash rides the event, and the campaign store keeps the bytes.
	entry.O = validation.SetOrAppend(entry.O, "verification",
		validation.VObj(harnessField(harness.Kind("miniprover"), rung, exec,
			bk, summary, validation.VNull())))
	// r20 F3: the rung is campaign STATE — links + event land together or
	// not at all (linksThenLog, the same law the minicertora path got).
	// The artifact registers AFTER the bind: a refused pair must not
	// leave a registered-but-never-logged report behind.
	// (F10: the PRIOR digest is captured BEFORE this bind's event exists
	// — asking after the append would always "find" the current run.)
	prior := autoprovePriorDigest(c, a.autoprove)
	// r24 F1 (critic F1): REGISTER FIRST and let the registry's own
	// hash vote on the bind. The old order (bind, then register) left
	// the event naming bytes the registry might never have held — a
	// swap in the window was permanent, audit-invisible, and the
	// transient stderr warning pointed at evidence nothing stored.
	// Now: register (which hashes the path), compare against the
	// mapped digest, and refuse — pruning the fresh row — when the
	// registry holds different bytes than the bind would name. A
	// refused linksThenLog likewise prunes: no registered-but-unlogged
	// ghost in either direction.
	rebindReason := "autoprove result re-bound"
	if prior != "" && prior != digest {
		rebindReason = fmt.Sprintf("autoprove re-bound over a CHANGED "+
			"report: prior event sha %s, this file %s", prior, digest)
		fmt.Fprintln(r.Err, "  WARNING: "+a.autoprove+" was previously "+
			"bound from a DIFFERENT report digest ("+prior[:12]+"… -> "+
			digest[:12]+"…) — "+rebindReason)
	}
	// r25 F4: bind a CONTENT-ADDRESSED COPY under the campaign, not the
	// mutable operator path. Refresh-overwrite is the destructive act:
	// a refused re-bind used to prune (or a successful one rewrite) the
	// row a PRIOR live bind's event cites — evidence ownership erased by
	// an unrelated later act. With the copy, each digest is its own
	// immutable row inside the store: prior citations always survive,
	// reconcile can never substitute a foreign byte into a pinned sha
	// (the copy IS the store), and the registry hash that VOTES on the
	// bind hashes exactly what the event names.
	copyPath, cerr := storeReportCopy(c, digest, raw)
	if cerr != nil {
		return t14ExitErr(2, "verify --autoprove: cannot store the "+
			"report copy: %v\n", cerr)
	}
	artID, err := c.RegisterOrRefresh("harness", copyPath,
		"miniprover report bound to "+a.autoprove+" (property "+
			a.property+", rollup "+dec.Outcome+")", nil,
		rebindReason)
	if err != nil {
		return err
	}
	regDig := ""
	if row, aerr := c.Artifact(artID); aerr == nil {
		regDig = objStr(row, "sha256")
	}
	if regDig != digest {
		_, _ = c.PruneArtifact(artID,
			"pruned: registry digest does not match the mapped report "+
				"bytes at bind time")
		return t14ExitErr(2, "verify --autoprove: the registry hashed "+
			"the report as %s but this bind maps %s — the bytes differ, "+
			"and an event would name evidence the store does not hold; "+
			"refused, artifact row pruned\n", regDig, digest)
	}
	if err := linksThenLog(c, func() error {
		return harnessSaveEntry(c, links, a.autoprove, entry)
	}, func() error {
		bkV := validation.VNull()
		if bk != nil {
			bkV = validation.VInt(int64(*bk))
		}
		edata := autoproveEventData(a.autoprove, rung, exec, summary,
			a.property, digest, bkV, rep)
		_, lerr := c.Log("harness_run", &a.autoprove, &edata)
		return lerr
	}); err != nil {
		// r25 F4: NEVER destroy evidence a LIVE bind still cites. The
		// REFUSED bind's own event does not exist (unwind restored it),
		// but an EARLIER bind may pin this row's digest — pruning it
		// then would burn the prior, honest rung on §11 for an
		// operator hiccup that touched nothing of theirs. Cite-check
		// first, BY ROW ID (r35 F1: the id is what an id-shaped
		// citation names), and prune only an orphan.
		if cited, cerr := artifactCitedByLiveBinds(c, artID); cerr == nil &&
			!cited {
			_, perr := c.PruneArtifact(artID,
				"pruned: bind refused — "+err.Error())
			if perr != nil {
				return fmt.Errorf("%w (AND the artifact row %s could not "+
					"be pruned: %v — a registered-but-unbound report; "+
					"reconcile by hand)", err, artID, perr)
			}
		} else {
			fmt.Fprintf(r.Err, "  NOTE: artifact %s stays: a live bind "+
				"cites its bytes; this refused bind left no event\n",
				artID)
		}
		return err
	}
	fmt.Fprintf(r.Out, "%s: %s — %s\n", a.autoprove, rung, summary)
	if !t26Truthy(rep, "review_independent") {
		fmt.Fprintln(r.Out, "  note: review was NOT independent (same or "+
			"no reviewer model) — the rollup rides one model's opinion")
	}
	if cm := objAt(rep, "capabilities_missing"); len(objKVs(cm)) > 0 {
		fmt.Fprintf(r.Out, "  verifier gaps at run time: %d capabilities "+
			"missing (degraded run; see tools/minicertora_conformance.py)\n",
			len(objKVs(cm)))
	}
	return nil
}

func objKVs(o validation.Value) []validation.KV {
	if o.Kind == validation.Obj {
		return o.O
	}
	if o.Kind == validation.Arr {
		out := make([]validation.KV, 0, len(o.A))
		for _, v := range o.A {
			out = append(out, validation.KV{V: v})
		}
		return out
	}
	return nil
}

func intFrom(o validation.Value, key string) int {
	v := objAt(o, key)
	switch v.Kind {
	case validation.Int:
		return int(v.I)
	case validation.Flt:
		return int(v.F)
	}
	return 0
}

func joinOrDash(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, "; ")
}

func joinHead(xs []string, n int) string {
	if len(xs) == 0 {
		return "none attributed"
	}
	if len(xs) > n {
		return strings.Join(xs[:n], ", ") + fmt.Sprintf(" (+%d more)",
			len(xs)-n)
	}
	return strings.Join(xs, ", ")
}

// orUnset rendered the schema gate's ABSENT state. r33 F3 moved the gate —
// sentence, state name and schema family — into harness (DecideReportSchema,
// harness.ReportSchemaMajor), so the default it applied lives there now and
// this verb holds no second copy of the wording.

// autoproveEventData is the harness_run payload for report-bound
// rungs: the shared four fields plus the report's own provenance
// (property title, sha256 of the bytes mapped, whether the review was
// independent at run time).
func autoproveEventData(invID, rung, exec, summary, property,
	digest string, bk validation.Value,
	rep validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "kind",
			V: validation.VStr(string(harness.Kind("miniprover")))},
		validation.KV{K: "rung", V: validation.VStr(rung)},
		validation.KV{K: "exec", V: validation.VStr(exec)},
		validation.KV{K: "invariant", V: validation.VStr(invID)},
		validation.KV{K: "summary", V: validation.VStr(summary)},
		validation.KV{K: "bounded_k", V: bk},
		// r23 F1: no proof sidecar on this path — the digest of ABSENCE
		// pins that fact so any slot-invented subtree burns the backstop.
		validation.KV{K: "proof_sha256",
			V: validation.VStr(harnessProofDigest(validation.VNull()))},
		validation.KV{K: "property", V: validation.VStr(property)},
		validation.KV{K: "report_sha256", V: validation.VStr(digest)},
		validation.KV{K: "review_independent",
			V: validation.VBool(t26Truthy(rep, "review_independent"))},
	)
}

// autoprovePropertyHolder scans harness_run events for a report+property
// pair already bound to some invariant. Returns (invariant, exec) of the
// FIRST binding (a re-bind of the same pair to the same invariant is a
// refresh, allowed; to a DIFFERENT invariant it is double credit).
func autoprovePropertyHolder(c *state.Campaign, property string) (string, string) {
	events, err := c.Events()
	if err != nil {
		// Unreadable ledger: the CALLER parses nothing silently either —
		// but refusing on a torn events file would block every bind; the
		// verify verb itself fails on the torn log BEFORE this point in
		// practice, and audit burns it. Return no-holder and let the
		// binding event itself become the second record.
		return "", ""
	}
	for _, e := range events {
		if objStr(e, "type") != "harness_run" {
			continue
		}
		d := objAt(e, "data")
		if !autoproveSameName(objStr(d, "property"), property) {
			continue
		}
		if inv := objStr(d, "invariant"); inv != "" {
			return inv, objStr(d, "exec")
		}
	}
	return "", ""
}

// autoprovePriorDigest: report_sha256 of the last miniprover bind of
// this invariant ("" if none) — the re-bind disclosure's baseline.
func autoprovePriorDigest(c *state.Campaign, invID string) string {
	events, err := c.Events()
	if err != nil {
		return ""
	}
	last := ""
	for _, e := range events {
		if objStr(e, "type") != "harness_run" {
			continue
		}
		d := objAt(e, "data")
		if objStr(d, "invariant") == invID &&
			objStr(d, "report_sha256") != "" {
			last = objStr(d, "report_sha256")
		}
	}
	return last
}

// autoproveSameName: property titles are AGENT-authored strings — the
// same verbatim-slop class r21 F2 fixed for verdicts. Attribution and
// consumption fold case + edges (display keeps the first spelling;
// identity is the folded form, so "P1" cannot launder a second bind
// nor dodge a suspect flag).
//
// r33 F2: the fold itself is harness.SamePropertyName — ONE implementation
// for the bind's holder scan, the SUSPECT gate and section 11's
// duplicate-attribution rail, which must collide on exactly the pairs this
// scan collides on. This is the cli's spelling of that function.
func autoproveSameName(a, b string) bool {
	return harness.SamePropertyName(a, b)
}

// artifactCitedByLiveBinds: does any live evidence still name this registry
// row? The implementation is state.ArtifactCitedByLiveBinds — the ONE cite
// predicate (r35 F1), which answers BOTH shapes: the row's sha256 as a bind
// pinned it (a harness_run event's report_sha256, or an exec record the event
// names hashing it in input_hashes/artifact_hashes — N1's EXEC rungs) AND the
// row's own id where an event or a registry field names it (a
// harness_scaffold event's ref, a verified_by link, a finding's artifact_id).
// This helper is the cli's spelling of that same decision so the bind's
// guard, the ghost-prune and the prune verb's warning cannot disagree.
func artifactCitedByLiveBinds(c *state.Campaign, id string) (bool,
	error) {
	cited, _, err := state.ArtifactCitedByLiveBinds(c, id)
	return cited, err
}

// harnessRowForPath: the registry row currently holding this path
// (resolved the registry's own way), if any.
func harnessRowForPath(c *state.Campaign, path string) (validation.Value,
	bool) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), false
	}
	want := state.ResolveArtifactPathFor(c, path)
	for _, arow := range objAt(st, "artifacts").A {
		if state.ResolveArtifactPathFor(c, objStr(arow, "path")) == want {
			return arow, true
		}
	}
	return validation.VNull(), false
}

// storeReportCopy writes the mapped bytes into the campaign store at a
// digest-named path (idempotent: an existing copy is verified, never
// overwritten — the rows are immutable by construction).
//
// r26 F2: the tmp+rename dance has a crash seam. A process killed after
// the write and before the rename leaves a tmp on disk; while that tmp
// was created 0444, the NEXT bind of the same digest opened it for
// writing, took EACCES as the owner, and refused that digest FOREVER — a
// transient crash became a permanent unavailability. The tmp is written
// 0600 so a leftover is always overwritable by its owner (the 0444 lands
// on the FINAL name only, after the rename), and a leftover LEGACY tmp is
// SWEPT rather than trusted — bytes that already hash to the digest are
// renamed into place (the crash cost nothing) and anything else is
// scratch, removed and rewritten. The tmp is fsynced and closed before
// the rename, matching validation.WriteJson: without it the rename can
// land before the bytes do, and a power loss publishes a zero-length or
// partial file under a content-addressed name the registry will then
// refuse.
//
// r27 hardening (F2/F3/F4/F5/F6), all in this one function:
//   - the store NEVER operates through a link (F2/F3). A symlink at the
//     tmp or the final name is a REFUSAL naming the shape: os.Rename
//     moves the LINK into place and the following os.Chmod FOLLOWS it,
//     which rewrote a victim's mode outside the campaign (observed
//     0644 -> 0444), and a link at the final name let a matching-bytes
//     target masquerade as the immutable copy. A directory/fifo/device
//     at either name is the same refusal class (F5) — a non-empty
//     directory at the tmp name used to wedge that digest forever
//     behind a message that misdiagnosed it as crash scratch.
//   - the scratch name is PER-CALL unique (F4), so two processes binding
//     one digest never share it; a rename that loses to a writer which
//     published the same digest is accepted only after re-reading the
//     final path and hashing it back to the digest.
//   - the durability step is CHECKED, not swallowed (F6): a directory
//     that cannot be opened for fsync is surfaced with its path and its
//     error, and the 0444 mode itself is fsynced after the chmod.
//
// r28 hardening (F4 + adoption sealing) adds the two halves the same
// discipline was missing:
//   - the DIRECTORY the store writes in is verified BEFORE anything is
//     written (F4). storeRefuseNonRegular guards the two names, but
//     os.MkdirAll follows a symlink, so a link at artifacts/reports made
//     this function write (and chmod 0444) a file in a directory outside
//     the campaign. A symlink/non-directory at the reports dir — or at
//     the artifacts dir above it — is refused by shape; the store must
//     live inside the campaign.
//   - an ADOPTED copy (bytes already at the final name) is sealed 0444
//     after its bytes are verified, exactly like a written one; a bind
//     that found a planted 0646 file used to hand that path back as the
//     read-only copy the docs promise. A failed seal is a refusal, never
//     an unsealed path.
func storeReportCopy(c *state.Campaign, digest string,
	raw []byte) (string, error) {
	dir := filepath.Join(c.ArtifactsDir, "reports")
	// r28 F4: the DIRECTORY the store writes in is checked before any
	// write, not just the two names inside it. os.MkdirAll FOLLOWS a
	// symlink, so a link at <campaign>/artifacts/reports pointing at
	// /tmp/victimDir made this function create /tmp/victimDir/report-
	// <sha>.json (mode 0444) — a write AND a chmod outside the campaign,
	// with no audit-visible trace: storeRefuseNonRegular lstat-checks the
	// final and the scratch NAMES, and the directory above them was never
	// inspected. The store is a directory the campaign owns: lstat both
	// levels, create what is absent, refuse any symlink (or non-directory)
	// by shape instead of resolving through it.
	if err := storeEnsureStoreDir(c.ArtifactsDir, "artifacts directory"); err != nil {
		return "", err
	}
	if err := storeEnsureStoreDir(dir, "report store"); err != nil {
		return "", err
	}
	// Full digest in the NAME, not a 12-hex prefix: a content-addressed
	// store whose name is truncated can collide, and the collision arm
	// REFUSES a legitimate bind (availability hazard for zero benefit).
	p := filepath.Join(dir, "report-"+digest+".json")
	// r27 F3: the FINAL name must be a REGULAR file the store itself
	// owns. os.ReadFile follows a link, so a symlink here whose target
	// held the digest was accepted as the immutable copy — and
	// rewriting that target later made §11 burn the honest bind with
	// "cannot be re-read from the store".
	if err := storeRefuseNonRegular(p); err != nil {
		return "", err
	}
	if cur, err := os.ReadFile(p); err == nil {
		if validation.Sha256Hex(cur) == digest {
			// r28 (adoption sealing): a pre-existing copy whose bytes
			// match is ADOPTED, and adoption owes the copy the same 0444
			// the write path publishes. The audit planted a matching-
			// bytes file at the final name with mode 0646 and it
			// survived the bind: the row said "immutable copy", the
			// docs promised read-only, and the bytes on disk said
			// otherwise. Seal it after verifying the bytes, and refuse
			// when the seal fails — a path this call could not seal is
			// not one it can hand back as the immutable copy.
			if serr := storeSeal(dir, p); serr != nil {
				return "", serr
			}
			return p, nil // the honest copy already stands
		}
		return "", fmt.Errorf("%s exists with foreign bytes (impossible "+
			"under a sha-named path: a prior collision or a tamper)", p)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	// Sweep the crash seam of the LEGACY fixed tmp name: a leftover tmp
	// whose bytes ARE the digest was written by an earlier run of this
	// very call — finish its rename instead of redoing the write.
	// r27 F2/F5 run FIRST: a link, directory, fifo or device at that
	// name is not scratch, it is a refusal.
	legacy := p + ".tmp"
	if err := storeRefuseNonRegular(legacy); err != nil {
		return "", err
	}
	if cur, err := os.ReadFile(legacy); err == nil &&
		validation.Sha256Hex(cur) == digest {
		if rerr := os.Rename(legacy, p); rerr == nil {
			if err := storeSeal(dir, p); err != nil {
				return "", err
			}
			return p, nil
		} else if !os.IsNotExist(rerr) {
			return "", rerr
		}
		// A concurrent writer took the legacy tmp and published this
		// digest: succeed only against an honest final copy.
		return storeAdoptPublished(dir, p, digest)
	}
	// Anything else at the legacy name is scratch, never evidence — and
	// it may carry the old 0444 mode, which its own owner cannot open
	// for writing. Remove it (the directory is what grants us that, not
	// the file) so the stale mode can never deny the digest it names.
	if err := os.Remove(legacy); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot clear the scratch file %s "+
			"left by an interrupted store: %w", legacy, err)
	}
	// r27 F4: the scratch name is PER-CALL unique — os.CreateTemp's
	// random suffix, the same shape validation.WriteJson uses
	// (name.tmp-<rand>: recognisable as a crash leftover, one writer per
	// scratch file) — so two processes binding one digest never share
	// scratch. The old fixed name made the loser's os.Rename return
	// ENOENT and exit 2 with a raw "no such file or directory" on the
	// very path the docs call idempotent (reproduced 4/8 and 2/10
	// rounds). CreateTemp's O_EXCL is the other half: whatever a hostile
	// writer planted at a guessed name is never written through — the
	// call simply gets a fresh name. The defer is the whole failure-path
	// story: this call's scratch never accumulates.
	fh, err := os.CreateTemp(dir, filepath.Base(p)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("cannot create the report scratch for %s "+
			"in %s: %w", digest, dir, err)
	}
	tt := fh.Name()
	defer func() { _ = os.Remove(tt) }()
	// Belt and braces on the exact name we are about to write through.
	if err := storeRefuseNonRegular(tt); err != nil {
		fh.Close()
		return "", err
	}
	// The create mode is filtered by umask, so the 0600 is set on the
	// OPEN handle; and the Sync below must be ours to check — a
	// swallowed fsync error is the crash seam this close exists for.
	if _, err := fh.Write(raw); err != nil {
		fh.Close()
		return "", err
	}
	if err := fh.Chmod(0o600); err != nil {
		fh.Close()
		return "", err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return "", fmt.Errorf("cannot fsync the report tmp %s: %w "+
			"(the rename must not publish bytes the disk never got)",
			tt, err)
	}
	if err := fh.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tt, p); err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		// r27 F4(b): the tmp vanished under the rename because another
		// writer published the identical digest. That is a lost race,
		// not a failure — adopt the published copy if (and only if) its
		// bytes hash to the digest this bind names.
		return storeAdoptPublished(dir, p, digest)
	}
	// 0444 lands AFTER the rename: the tmp name must stay owner-writable
	// for the life of the crash window, or a kill -9 between the two
	// steps re-creates the wedge this rail removes. The seal fsyncs the
	// mode and the directory entry (r27 F6).
	if err := storeSeal(dir, p); err != nil {
		return "", err
	}
	return p, nil
}

// storeSyncRefused: a Sync failure that means the FILESYSTEM cannot do
// it, not that the durability step silently did not happen. Everything
// else is surfaced (r27 F6).
func storeSyncRefused(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.ENOSYS)
}

// storePathShape names what was actually found at a store path, so the
// refusal can state the exact shape observed (r27 F5). The regular-file
// case became reachable with r28 F4's directory rail: a plain FILE where a
// store DIRECTORY belongs is named as one ("regular file", not its raw
// mode string) in the refusal that tells the operator the store must live
// inside the campaign.
func storePathShape(fi os.FileInfo) string {
	m := fi.Mode()
	switch {
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "directory"
	case m&os.ModeNamedPipe != 0:
		return "fifo"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeCharDevice != 0:
		return "character device"
	case m&os.ModeDevice != 0:
		return "block device"
	case m.IsRegular():
		return "regular file"
	}
	return m.String()
}

// storeEnsureStoreDir is the r28 F4 directory rail: the store may only
// write into a REAL directory the campaign owns. lstat (never Stat) the
// path; a missing one is created 0755 (MkdirAll, then re-lstat so a link
// planted in the race is still seen as a link); an existing symlink — or
// any other non-directory — is a REFUSAL naming the path and the shape
// found, because the store must live inside the campaign. Resolving
// through the link and continuing is exactly the escape this refuses:
// os.MkdirAll follows a link, so the write and its 0444 chmod land
// outside the campaign with no audit-visible trace.
func storeEnsureStoreDir(path, role string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if merr := os.MkdirAll(path, 0o755); merr != nil {
			return fmt.Errorf("cannot create the %s %s: %w", role, path,
				merr)
		}
		if fi, err = os.Lstat(path); err != nil {
			return err
		}
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("the %s %s is a %s, not a directory - the store "+
			"must live inside the campaign, never through a link (a "+
			"symlinked store directory writes the evidence outside it)",
			role, path, storePathShape(fi))
	}
	return nil
}

// storeRefuseNonRegular: the store never operates THROUGH an object.
// lstat (not Stat) both the tmp and the final name; a non-regular object
// is a REFUSAL naming its shape, never scratch to delete (r27 F2/F3/F5).
func storeRefuseNonRegular(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode().IsRegular() {
		// r27b: a HARDLINK is regular to lstat, so a shared inode walks
		// past the shape check — and a chmod through it rewrites the
		// mode of every other name for those bytes. The copy must be a
		// file the store ALONE names.
		if n, ok := storeLinkCount(fi); ok && n > 1 {
			return fmt.Errorf("the store path %s is a regular file with "+
				"%d hard links - the copy must be a file only the store "+
				"names (a shared inode means the read-only chmod "+
				"rewrites a foreign name too)", path, n)
		}
		return nil
	}
	return fmt.Errorf("the store path %s is a %s, not the copy - the "+
		"immutable record must be a regular file inside the campaign",
		path, storePathShape(fi))
}

// storeLinkCount reads the link count where the platform reports one.
func storeLinkCount(fi os.FileInfo) (uint64, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink), true
	}
	return 0, false
}

// storeAdoptPublished: a rename lost the race to a writer that published
// this digest. Success is honest ONLY if the final path is a regular file
// the store owns whose bytes hash to the digest; anything else is the
// refusal it deserves (r27 F3/F4).
func storeAdoptPublished(dir, p, digest string) (string, error) {
	if err := storeRefuseNonRegular(p); err != nil {
		return "", err
	}
	cur, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("the report scratch for %s vanished before "+
			"the rename and the store does not hold it: %w", digest, err)
	}
	if validation.Sha256Hex(cur) != digest {
		return "", fmt.Errorf("%s exists with foreign bytes (impossible "+
			"under a sha-named path: a prior collision or a tamper)", p)
	}
	if err := storeSeal(dir, p); err != nil {
		return "", err
	}
	return p, nil
}

// storeSeal publishes the immutable copy: 0444 ON the regular file, then
// fsync OF the file (so a crash cannot leave the copy 0600 while the docs
// promise 0444) and fsync of the directory entry that names it (so power
// loss cannot leave a registry row citing a file the disk never got).
// Only failures meaning "this filesystem cannot" are tolerated (r27 F6):
// an OPEN failure is surfaced with its path and its error — a reports
// directory the process cannot open (mode 0333 -> EACCES) used to skip
// the whole durability step silently in the name of best-effort.
func storeSeal(dir, p string) error {
	if err := storeRefuseNonRegular(p); err != nil {
		return err
	}
	if err := os.Chmod(p, 0o444); err != nil {
		return fmt.Errorf("cannot set the immutable mode 0444 on the "+
			"published copy %s: %w", p, err)
	}
	fh, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("cannot open the published copy %s to fsync its "+
			"0444 mode: %w", p, err)
	}
	serr := fh.Sync()
	fh.Close()
	if serr != nil && !storeSyncRefused(serr) {
		return fmt.Errorf("cannot fsync the published copy %s after the "+
			"0444 chmod: %w", p, serr)
	}
	d, derr := os.Open(dir)
	if derr != nil {
		return fmt.Errorf("cannot open the report store %s to fsync the "+
			"rename that published %s: %w", dir, p, derr)
	}
	dserr := d.Sync()
	d.Close()
	if dserr != nil && !storeSyncRefused(dserr) {
		return fmt.Errorf("cannot fsync the report store %s: %w",
			dir, dserr)
	}
	return nil
}
