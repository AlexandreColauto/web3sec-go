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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// autoproveReport is what we trust from the file, kept small on purpose.
const autoproveSchemaMajor = "1."

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
	sv := objStr(rep, "schema_version")
	if !strings.HasPrefix(sv, autoproveSchemaMajor) {
		return t14ExitErr(2, "verify --autoprove: report schema_version %s "+
			"is not understood (this build speaks %s0.x) — refusing to "+
			"best-effort a contract change\n",
			validation.PyReprStr(orUnset(sv, "ABSENT (pre-1.0 report)")),
			autoproveSchemaMajor)
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
		exec = "REPORT-" + digest[:12]
	}
	// The run-level gates FIRST: a rollup over a run the prover itself
	// refuses to publish is not evidence of anything.
	// r19 P2: publish_problems is the prover's own veto list — binding a
	// rollup over a report that carries problems (even with published
	// true, a contradiction the prover itself refuses to emit) launders
	// them; refuse and show them verbatim.
	probsPre := objAt(rep, "publish_problems")
	if probsPre.Kind != validation.Null && probsPre.Kind != validation.Arr {
		// r20 F6: the veto list is a LIST by contract — a scalar there is
		// either a lie or a bug; both refuse better than bind.
		return t14ExitErr(2, "verify --autoprove: malformed "+
			"publish_problems (kind %v, contract: array) — the veto list "+
			"is machine-authored; refusing to read a broken contract\n",
			probsPre.Kind)
	}
	if len(objKVs(probsPre)) > 0 {
		msgs := []string{}
		for _, pv := range probsPre.A {
			msgs = append(msgs, scalarStr(pv))
		}
		return t14ExitErr(2, "verify --autoprove: the report carries "+
			"publish_problems (%s)%s\n", joinOrDash(msgs),
			map[bool]string{
				true: " while claiming published — internally " +
					"contradictory; nothing binds",
				false: " — the run is unpublished; nothing binds",
			}[t26Truthy(rep, "published")])
	}
	if !t26Truthy(rep, "published") {
		probs := []string{}
		for _, p := range objAt(rep, "publish_problems").A {
			probs = append(probs, scalarStr(p))
		}
		return t14ExitErr(2, "verify --autoprove: the prover did NOT "+
			"publish this run — nothing is blessed (problems: %s)\n",
			joinOrDash(probs))
	}
	po := objAt(rep, "property_outcomes")
	if po.Kind != validation.Obj {
		return t14ExitErr(2, "verify --autoprove: report carries no "+
			"property_outcomes map — contract broken\n")
	}
	prop, ok := fieldOf(po, a.property)
	if !ok {
		names := []string{}
		for _, kv := range po.O {
			names = append(names, kv.K)
		}
		return t14ExitErr(2, "verify --autoprove: property %s is not in "+
			"this run (the prover attempted: %s) — exact-match only\n",
			validation.PyReprStr(a.property), joinOrDash(names))
	}
	// r22 F2: the prover records review_error precisely so "no findings"
	// and "no review" never look alike — a run whose review role
	// CRASHED carries an EMPTY findings list that means nothing. Law:
	// an unmade check is never a cleared check.
	if re := objStr(rep, "review_error"); re != "" {
		return t14ExitErr(2, "verify --autoprove: the independent review "+
			"NEVER RAN (%s) — PROVEN binds without it only by "+
			"inattention; refusing\n", re)
	}
	if v := objAt(rep, "review_findings"); v.Kind != validation.Arr {
		// r22 F5: the twin ALWAYS emits an array — null, absent, or
		// scalar are all foreign contracts. An unreadable gate input
		// reads as "nothing flagged" to nothing: refuse.
		return t14ExitErr(2, "verify --autoprove: malformed "+
			"review_findings (kind %v, contract: array) — the gate "+
			"reads the review's output; a broken one is never empty "+
			"enough to pass\n", v.Kind)
	}
	if sus := autoproveSuspects(rep, a.property); sus != "" {
		return t14ExitErr(2, "verify --autoprove: the independent review "+
			"flagged property %s as SUSPECT — %s — a PROVEN verdict next "+
			"to a suspect review is the most expensive state there is; "+
			"the rung is refused, fix the rule or waive with reason\n",
			a.property, sus)
	}
	outcome := objStr(prop, "outcome")
	perRule := objAt(prop, "per_rule")
	// r24 F3: the bound is READ TYPED — a float is truncation, a
	// string/big is a foreign shape, and the twin's VerifierFlags
	// raises for loop_bound<1, so 0 is by definition NOT twin output
	// (r25 F3: honoring k=0 would bless a proof-about-nothing with a
	// loudly stated bound). r25 F2: the decision itself moved to
	// harness.MapReport — the audit re-derives from the SAME function,
	// so bind-time and read-time can never disagree.
	k, kStated, kOK, kWhy := harness.BoundFromFlags(objAt(rep, "flags"))
	if !kOK {
		return t14ExitErr(2, "verify --autoprove: flags.loop_bound %s; "+
			"this report is not a twin output and will not bind\n", kWhy)
	}
	rung, summary, bk := harness.MapReport(outcome, perRule, k, kStated)
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
			a.property+", rollup "+outcome+")", nil,
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
		// first: prune only an orphan.
		if cited, cerr := artifactCitedByLiveBinds(c, regDig); cerr == nil &&
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

// autoproveSuspects renders the reasons of SUSPECT review findings for
// one property ("" when none) — PROVEN must not bind over them.
func autoproveSuspects(rep validation.Value, property string) string {
	out := []string{}
	for _, f := range objAt(rep, "review_findings").A {
		// r20 F2: the prover stores the review LLM's verdict VERBATIM —
		// "SUSPECT"/"Suspect" is the same word and the same danger; the
		// gate is case-insensitive by law.
		// r21 F2: the gate is FAIL-CLOSED against the shapes an LLM
		// review actually emits: verdict is TRIMMED as well as
		// case-folded (" suspect " is the same flag), and a finding
		// element that is not an object (a bare string was the critic's
		// dodge) has NO property to match — it counts against EVERY
		// property. Unparseable warning is never cleared warning.
		if f.Kind != validation.Obj {
			out = append(out, "malformed review finding (non-object): "+
				scalarStr(f))
			continue
		}
		v := strings.ToLower(strings.TrimSpace(objStr(f, "verdict")))
		if v != "" && v != "suspect" {
			continue
		}
		if f2 := objAt(f, "property"); f2.Kind != validation.Str {
			out = append(out, "suspect-flagged finding with no property "+
				"attribution — counted against every property")
			continue
		}
		if !autoproveSameName(objStr(f, "property"), property) {
			continue
		}
		out = append(out, scalarStr(objAt(f, "reason")))
	}
	return strings.Join(out, "; ")
}

func fieldOf(o validation.Value, key string) (validation.Value, bool) {
	for _, kv := range objKVs(o) {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
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

func orUnset(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

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
func autoproveSameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// artifactCitedByLiveBinds: does any harness_run event still name this
// digest as its report_sha256? (The refused bind wrote none — the
// unwind restored the ledger — so this asks about the OTHER rows.)
func artifactCitedByLiveBinds(c *state.Campaign, dig string) (bool,
	error) {
	if dig == "" {
		return false, nil
	}
	events, err := c.Events()
	if err != nil {
		return false, err
	}
	for _, ev := range events {
		if objStr(ev, "type") != "harness_run" {
			continue
		}
		if objStr(objAt(ev, "data"), "report_sha256") == dig {
			return true, nil
		}
	}
	return false, nil
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
// the write and before the rename leaves report-<digest>.json.tmp on
// disk; while that tmp was created 0444, the NEXT bind of the same
// digest opened it for writing, took EACCES as the owner, and refused
// that digest FOREVER — a transient crash became a permanent
// unavailability. Two disciplines close it: the tmp is written 0600 so
// a leftover is always overwritable by its owner (the 0444 lands on the
// FINAL name only, after the rename, and is still immutable-by-
// convention evidence), and a leftover tmp is SWEPT rather than
// trusted — bytes that already hash to the digest are renamed into
// place (the crash cost nothing) and anything else is scratch, removed
// and rewritten (only the digest-named final file is evidence). The tmp
// is also fsynced and closed before the rename, matching
// validation.WriteJson: without it the rename can land before the bytes
// do, and a power loss publishes a zero-length or partial file under a
// content-addressed name the registry will then refuse.
func storeReportCopy(c *state.Campaign, digest string,
	raw []byte) (string, error) {
	dir := filepath.Join(c.ArtifactsDir, "reports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// Full digest in the NAME, not a 12-hex prefix: a content-addressed
	// store whose name is truncated can collide, and the collision arm
	// REFUSES a legitimate bind (availability hazard for zero benefit).
	p := filepath.Join(dir, "report-"+digest+".json")
	if cur, err := os.ReadFile(p); err == nil {
		if validation.Sha256Hex(cur) == digest {
			return p, nil // the honest copy already stands
		}
		return "", fmt.Errorf("%s exists with foreign bytes (impossible "+
			"under a sha-named path: a prior collision or a tamper)", p)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	tmp := p + ".tmp"
	// Sweep the crash seam: a leftover tmp whose bytes ARE the digest was
	// written by an earlier run of this very call — finish its rename
	// instead of redoing the write.
	if cur, err := os.ReadFile(tmp); err == nil &&
		validation.Sha256Hex(cur) == digest {
		if err := os.Rename(tmp, p); err != nil {
			return "", err
		}
		if err := os.Chmod(p, 0o444); err != nil {
			return "", err
		}
		return p, nil
	}
	// Anything else at the tmp name is scratch, never evidence — and it
	// may carry the old 0444 mode, which its own owner cannot open for
	// writing. Remove it (the directory is what grants us that, not the
	// file) so the stale mode can never deny the digest it names.
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("cannot clear the scratch file %s "+
			"left by an interrupted store: %w", tmp, err)
	}
	// Open explicitly rather than os.WriteFile: the create mode is
	// filtered by umask, and the Sync below must be ours to check — a
	// swallowed fsync error is the crash seam this close exists for.
	fh, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
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
			tmp, err)
	}
	if err := fh.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		return "", err
	}
	// 0444 lands AFTER the rename: the tmp name must stay owner-writable
	// for the life of the crash window, or a kill -9 between the two
	// steps re-creates the wedge this rail removes.
	if err := os.Chmod(p, 0o444); err != nil {
		return "", err
	}
	return p, nil
}
