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
	k := intFrom(objAt(rep, "flags"), "loop_bound")
	var rung, summary string
	switch outcome {
	case "PROVEN":
		// r19 P1: the rollup is the prover's claim ABOUT its rule lines;
		// the rule-keyed values are the AUTHORITY (law 3 — a buggy or
		// doctored report whose per_rule contradicts its PROVEN rollup
		// must not bind). Empty per_rule of ANY shape is UNATTRIBUTED.
		kvs := objKVs(perRule)
		if perRule.Kind == validation.Arr || len(kvs) == 0 {
			rung = harness.RungInconclusive
			if perRule.Kind == validation.Arr {
				summary = "inconclusive (malformed per_rule: an ARRAY has " +
					"no rule keys — the mapper is rule-keyed by contract)"
			} else {
				summary = "inconclusive (UNATTRIBUTED: the property claims " +
					"PROVEN with no per-rule outcomes)"
			}
			break
		}
		bad := []string{}
		for _, kv := range kvs {
			if scalarStr(kv.V) != "PROVEN" {
				bad = append(bad, kv.K+"="+scalarStr(kv.V))
			}
		}
		if len(bad) > 0 {
			rung = harness.RungInconclusive
			summary = "inconclusive (report-contradiction: rollup says " +
				"PROVEN but per_rule carries " + joinHead(bad, 5) + ")"
			break
		}
		n := len(kvs)
		if k > 0 {
			summary = fmt.Sprintf("autoproved bounded (k=%d, %d rules)", k, n)
		} else {
			// r20 F11: "bounded" with no bound stated must SAY so — the
			// rung names the absence, it does not hide behind the word.
			summary = fmt.Sprintf("autoproved bounded (bound UNSTATED, %d "+
				"rules)", n)
		}
		rung = harness.RungProvedBounded
	case "VIOLATED":
		viol := []string{}
		for _, kv := range objKVs(perRule) {
			if scalarStr(kv.V) == "VIOLATED" {
				viol = append(viol, kv.K)
			}
		}
		if len(viol) == 0 {
			// r20 F5: symmetry — a VIOLATED rollup whose per_rule carries
			// NO violated line is the same contradiction in the other
			// direction; a counterexample names its refuted rule or is a
			// gap.
			rung = harness.RungInconclusive
			summary = "inconclusive (report-contradiction: rollup says " +
				"VIOLATED but per_rule carries no violated line)"
			break
		}
		summary = "counterexample (autoprove refuted rules: " +
			joinHead(viol, 5) + ")"
		rung = harness.RungCounterexample
	default:
		// OUT_OF_FRAGMENT / INCONCLUSIVE / REFUSED / UNATTRIBUTED and
		// any FUTURE outcome string the prover adds: gaps, never passes.
		rung = harness.RungInconclusive
		summary = "inconclusive (prover rollup: " + outcome + ")"
	}
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
	var bk *int
	if rung == harness.RungProvedBounded && k > 0 {
		bk = &k
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
		return err
	}
	// r20 F10: a re-bind over a DIFFERENT report digest (bytes edited on
	// disk since the first bind) must say so — the reason row names old
	// and new sha, so the refresh cannot launder a substituted report.
	rebindReason := "autoprove result re-bound"
	if prior != "" && prior != digest {
		rebindReason = fmt.Sprintf("autoprove re-bound over a CHANGED "+
			"report: prior event sha %s, this file %s", prior, digest)
		fmt.Fprintln(r.Err, "  WARNING: "+a.autoprove+" was previously "+
			"bound from a DIFFERENT report digest ("+prior[:12]+"… -> "+
			digest[:12]+"…) — "+rebindReason)
	}
	artID, err := c.RegisterOrRefresh("harness", a.report,
		"miniprover report bound to "+a.autoprove+" (property "+
			a.property+", rollup "+outcome+")", nil,
		rebindReason)
	if err != nil {
		return err
	}
	// r23 (sharpest idea): the event pins the digest of the bytes we
	// MAPPED; the registry hashed the PATH later — a swap in that
	// window left provenance naming bytes nothing ever checked. Compare
	// the two, before and after: the pre-check refuses the common
	// single swap (event not yet bound, nothing to unwind); the
	// post-check catches the pathological double-swap and says so
	// where the rung lives — an admitted skew the rebind rail makes
	// loud, never a silent "consistent".
	if cur, rerr := os.ReadFile(a.report); rerr != nil ||
		validation.Sha256Hex(cur) != digest {
		fmt.Fprintf(r.Err, "  WARNING: %s's report bytes changed again "+
			"after binding (mapped sha %s, artifact %s now holds %s) — "+
			"the event names the MAPPED bytes; re-verify against them\n",
			a.autoprove, digest[:12], artID,
			validation.Sha256Hex(func() []byte {
				b, _ := os.ReadFile(a.report)
				return b
			}())[:12])
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
