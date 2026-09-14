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
	exec := a.execID
	if exec == "" {
		// No sandbox EXEC wrapped this report: the digest identifies
		// what was mapped, and says so — an honest "report-only"
		// provenance row, not a fabricated EXEC id.
		exec = "REPORT-" + digest[:12]
	}
	// The run-level gates FIRST: a rollup over a run the prover itself
	// refuses to publish is not evidence of anything.
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
		if perRule.Kind != validation.Arr && len(objKVs(perRule)) == 0 {
			// The prover's own rule 2: no lines is never PROVEN.
			rung = harness.RungInconclusive
			summary = "inconclusive (UNATTRIBUTED: the property claims " +
				"PROVEN with no per-rule outcomes)"
			break
		}
		n := len(objKVs(perRule))
		if k > 0 {
			summary = fmt.Sprintf("autoproved bounded (k=%d, %d rules)", k, n)
		} else {
			summary = fmt.Sprintf("autoproved bounded (%d rules)", n)
		}
		rung = harness.RungProvedBounded
	case "VIOLATED":
		viol := []string{}
		for _, kv := range objKVs(perRule) {
			if scalarStr(kv.V) == "VIOLATED" {
				viol = append(viol, kv.K)
			}
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
	if err := harnessSaveEntry(c, links, a.autoprove, entry); err != nil {
		return err
	}
	if _, err := c.RegisterOrRefresh("harness", a.report,
		"miniprover report bound to "+a.autoprove+" (property "+
			a.property+", rollup "+outcome+")", nil,
		"autoprove result re-bound"); err != nil {
		return err
	}
	data := validation.VObj(
		validation.KV{K: "rung", V: validation.VStr(rung)},
		validation.KV{K: "exec", V: validation.VStr(exec)},
		validation.KV{K: "invariant", V: validation.VStr(a.autoprove)},
		validation.KV{K: "summary", V: validation.VStr(summary)},
		validation.KV{K: "property", V: validation.VStr(a.property)},
		validation.KV{K: "report_sha256", V: validation.VStr(digest)},
		validation.KV{K: "review_independent",
			V: validation.VBool(t26Truthy(rep, "review_independent"))},
	)
	if _, err := c.Log("harness_run", &a.autoprove, &data); err != nil {
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
		if objStr(f, "property") != property {
			continue
		}
		if v := objStr(f, "verdict"); v != "" && v != "suspect" {
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
